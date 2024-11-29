package syso

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Stat struct {
	SyscallNr uint64 `json:"syscall_nr"`
	Library   string `json:"library"`
	Pid       int32  `json:"pid"`
	Ppid      int32  `json:"ppid"`
	Timestamp uint64 `json:"timestamp"`
}

var missedStat = Stat{Library: "MISSED_BUFFER_FULL"}

var (
	ErrStatSaveFailed = errors.New("failed to save stat")
	ErrReadTimeout    = errors.New("bpf read timeout exceeded")

	rbfIndex = int32(0)
)

type Tracer struct {
	logger    *zap.SugaredLogger
	output    io.WriteSeeker
	maps      *ProcMaps
	objects   *sysoObjects
	startTime int64  // unix time
	firstStat uint64 // ktime (nanoseconds since boot)
}

// NewTracer configures a tracer to monitor application syscalls.
func NewTracer(logger *zap.SugaredLogger, output io.WriteSeeker, maps *ProcMaps) (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to clear memlock: %w", err)
	}

	t := Tracer{
		logger:  logger,
		output:  output,
		maps:    maps,
		objects: &sysoObjects{},
	}

	if err := loadSysoObjects(t.objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load bpf objects: %w", err)
	}

	return &t, nil
}

// Trace will trace system calls that happen when executing the executable.
func (t *Tracer) Trace(ctx context.Context, executable string, args ...string) error {
	if _, err := t.output.Write([]byte("[")); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	t.logger.Infow("tracing program execution", "executable", executable)

	pid := os.Getpid()

	if err := t.objects.FollowPidMap.Put(int32(pid), true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	if err := t.objects.ScEventsFullMap.Put(&rbfIndex, false); err != nil {
		return fmt.Errorf("failed to register ringbuf empty: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: t.objects.sysoPrograms.RawTpSysEnter,
	})
	if err != nil {
		return fmt.Errorf("failed to attack to raw tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(t.objects.ScEventsMap)
	if err != nil {
		return fmt.Errorf("failed to get reader to sc_events_map: %w", err)
	}
	defer rd.Close()

	cmd := exec.Command(executable, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	stopper := make(chan os.Signal)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eventsChan := make(chan sysoScEvent, 512)
	defer close(eventsChan)

	rbFullChan := make(chan struct{})
	defer close(rbFullChan)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executable: %w", err)
	}
	defer cmd.Wait()

	var group errgroup.Group

	group.Go(func() error {
		<-stopper
		cancel()
		rd.Close()
		t.logger.Infow("received interrupt: exiting...")
		return nil
	})

	group.Go(
		func() error {
			t.startTime = time.Now().UnixNano()
			return t.monitorScEvents(ctx, rd, eventsChan)
		})

	group.Go(
		func() error {
			return t.monitorScEventsFull(ctx, rbFullChan)
		})

	group.Go(
		func() error {
			return t.listen(ctx, eventsChan, rbFullChan)
		})

	if err := group.Wait(); err != nil {
		return err
	}

	if _, err := t.output.Seek(-1, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek back a byte: %w", err)
	}

	if _, err := t.output.Write([]byte("]")); err != nil {
		return fmt.Errorf("failed to write closing bracket")
	}

	return nil
}

func (t *Tracer) monitorScEventsFull(ctx context.Context, rbFullChan chan struct{}) error {
	var ringbufFull bool

	prevFull := false

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		prevFull = ringbufFull

		if err := t.objects.ScEventsFullMap.Lookup(&rbfIndex, &ringbufFull); err != nil {
			return fmt.Errorf("failed to check if ringbuffer is full: %w", err)
		}

		if !ringbufFull || (ringbufFull && prevFull) {
			continue
		}

		// only send when state changes from "not full" to "full" to avoid cluttering stats
		rbFullChan <- struct{}{}
	}
}

func (t *Tracer) monitorScEvents(ctx context.Context, rd *ringbuf.Reader, eventsChan chan sysoScEvent) error {
	var event sysoScEvent

	for {
		select {
		case <-ctx.Done():
			rd.Close()
		default:
		}

		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			t.logger.Info("ringbuffer closed, exiting...")

			return nil
		} else if err != nil {
			return fmt.Errorf("failed to read from ringbuffer: %w", err)
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("failed to parse binary from bpf map: %w", err)
		}

		eventsChan <- event
	}
}

func (t *Tracer) listen(ctx context.Context, eventsChan chan sysoScEvent, rbFullChan chan struct{}) error {
	for {
		select {
		case <-ctx.Done():
			t.logger.Infow("trace finished", "timestamp", time.Now().UnixNano())

			return nil
		case event := <-eventsChan:
			if err := t.reportEvent(event); err != nil {
				return fmt.Errorf("failed to report event: %w", err)
			}
		case <-rbFullChan:
			if err := t.reportMissedStat(); err != nil {
				return fmt.Errorf("failed to report missed stat: %w", err)
			}
		}
	}
}

func (t *Tracer) reportEvent(event sysoScEvent) error {
	if t.firstStat == 0 {
		t.firstStat = event.Timestamp
	}

	sharedLib, err := t.maps.AssignPC(event.Pc, event.Pid, event.Dirty)
	if err != nil {
		t.logger.Errorw(
			"failed to assign pc to shared library: ",
			"pc", event.Pc,
			"pid", event.Pid,
			"ppid", event.Ppid,
			"err", err,
		)
	}

	if sharedLib == "" {
		sharedLib = "FAILED"
	}

	return t.reportStat(Stat{
		SyscallNr: event.SyscallNr,
		Library:   sharedLib,
		Pid:       event.Pid,
		Ppid:      event.Ppid,
		Timestamp: event.Timestamp,
	})
}

func (t *Tracer) reportStat(stat Stat) error {
	bts, err := json.Marshal(stat)
	if err != nil {
		return fmt.Errorf("failed to marshal stat to json: %w", err)
	}

	n, err := t.output.Write(bts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStatSaveFailed, err)
	}

	if n != len(bts) {
		return fmt.Errorf("%w: bits written (%d) != bits to write (%d)", n, len(bts))
	}

	if _, err := t.output.Write([]byte(",")); err != nil {
		return fmt.Errorf("failed to add comma: %w", err)
	}

	return nil
}

func (t *Tracer) reportMissedStat() error {
	// may seem strange to get a timestamp in userspace: why cant this be done in the kernel?
	//
	// tracing programs don't support spinlocking yet, so can't safely update timestamps in a BPF_MAP_TYPE_HASH.
	// since just an estimate is required, this is fine: if it becomes a problem, can change later.
	//
	// note: not a problem with ring buffers as ring buffers guarantee event ordering to be preserved.
	now := time.Now().UnixNano()

	// estimate ktime
	missedStat.Timestamp = t.firstStat + uint64(now-t.startTime)

	return t.reportStat(missedStat)
}
