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

type MissedStats struct {
	RingBufFull     uint64 `json:"ringbuf_full"`
	GetParentFailed uint64 `json:"get_parent_failed"`
	GetPTRegsFailed uint64 `json:"get_pt_regs_failed"`
}

// TODO: figure out some way to have this generated from the macro in bpf/syso.bpf.c
const nSysoFailureTypes = 3

var (
	ErrStatSaveFailed = errors.New("failed to save stat")
	ErrReadTimeout    = errors.New("bpf read timeout exceeded")
)

var commaNeeded bool

type Tracer struct {
	logger  *zap.SugaredLogger
	output  io.WriteSeeker
	maps    *ProcMaps
	objects *sysoObjects
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

	if err := t.initFollowMap(); err != nil {
		return fmt.Errorf("failed to initialise follow map: %w", err)
	}

	if err := t.initMissedMap(); err != nil {
		return fmt.Errorf("failed to initialise error map: %w", err)
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
			return t.monitorScEvents(ctx, rd, eventsChan)
		})

	group.Go(
		func() error {
			return t.listen(ctx, eventsChan)
		})

	if err := group.Wait(); err != nil {
		return err
	}

	if err := t.writeMissedStats(); err != nil {
		return fmt.Errorf("failed to write missed stats: %w", err)
	}

	if _, err := t.output.Write([]byte("]")); err != nil {
		return fmt.Errorf("failed to write closing bracket")
	}

	return nil
}

func (t *Tracer) initFollowMap() error {
	pid := os.Getpid()

	if err := t.objects.FollowPidMap.Put(int32(pid), true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}
	return nil
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

func (t *Tracer) listen(ctx context.Context, eventsChan chan sysoScEvent) error {
	for {
		select {
		case <-ctx.Done():
			t.logger.Infow("trace finished", "timestamp", time.Now().UnixNano())

			return nil
		case event := <-eventsChan:
			if err := t.reportEvent(event); err != nil {
				return fmt.Errorf("failed to report event: %w", err)
			}
		}
	}
}

func (t *Tracer) reportEvent(event sysoScEvent) error {
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
	if commaNeeded {
		if _, err := t.output.Write([]byte(",")); err != nil {
			return fmt.Errorf("failed to write comma: %w", err)
		}
	} else {
		commaNeeded = true
	}

	encoder := json.NewEncoder(t.output)
	if err := encoder.Encode(stat); err != nil {
		return fmt.Errorf("failed to encode stat as JSON: %w", err)
	}

	return nil
}

func (t *Tracer) initMissedMap() error {
	zero := uint64(0)

	// this is okay in >=go1.22
	// see https://go.dev/wiki/LoopvarExperiment#what-is-the-solution
	for i := int32(0); i < nSysoFailureTypes; i++ {
		if err := t.objects.ErrMap.Put(&i, &zero); err != nil {
			return fmt.Errorf("failed to initialise errmap %d to zero: %w", i, err)
		}
	}

	return nil
}

func (t *Tracer) readMissedMap() (*MissedStats, error) {
	var (
		rbFull       uint64
		parentFailed uint64
		ptRegsFailed uint64
	)

	// not allowed to take an address of a constant, hence the assignment
	i := sysoFailureTypeRINGBUF_FULL
	if err := t.objects.ErrMap.Lookup(&i, &rbFull); err != nil {
		return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
	}

	i = sysoFailureTypeGET_PARENT_FAILED
	if err := t.objects.ErrMap.Lookup(&i, &parentFailed); err != nil {
		return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
	}

	i = sysoFailureTypeGET_PT_REGS_FAILED
	if err := t.objects.ErrMap.Lookup(&i, &ptRegsFailed); err != nil {
		return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
	}

	t.logger.Infow(
		"missed syscalls",
		"ringbuf-full", rbFull,
		"get-parent-failed", parentFailed,
		"get-pt-regs-failed", ptRegsFailed,
	)

	return &MissedStats{
		RingBufFull:     rbFull,
		GetParentFailed: parentFailed,
		GetPTRegsFailed: ptRegsFailed,
	}, nil
}

func (t *Tracer) writeMissedStats() error {
	if commaNeeded {
		if _, err := t.output.Write([]byte(",")); err != nil {
			return fmt.Errorf("failed to write comma: %w", err)
		}
	}

	missed, err := t.readMissedMap()
	if err != nil {
		return fmt.Errorf("failed to read missed map: %w", err)
	}

	encoder := json.NewEncoder(t.output)
	if err := encoder.Encode(missed); err != nil {
		return fmt.Errorf("failed to encode missed stats: %w", err)
	}

	return nil
}
