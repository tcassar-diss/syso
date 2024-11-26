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
)

const BPFTimeoutDur = 1 * time.Second

var (
	ErrRingbufFull    = errors.New("ringbuffer full")
	ErrStatSaveFailed = errors.New("failed to save stat")
	ErrReadTimeout    = errors.New("bpf read timeout exceeded")

	rbfIndex = int32(1)
)

type Tracer struct {
	logger  *zap.SugaredLogger
	output  io.Writer
	maps    *ProcMaps
	objects *sysoObjects
}

// NewTracer configures a tracer to monitor application syscalls.
func NewTracer(logger *zap.SugaredLogger, output io.Writer, maps *ProcMaps) (*Tracer, error) {
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

	stopper := make(chan os.Signal)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	cmd := exec.Command(executable, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executable: %w", err)
	}
	defer cmd.Wait()

	go func() {
		select {
		case <-ctx.Done():
			rd.Close()
			t.logger.Infow("context cancelled: exiting...")
		case interrupt := <-stopper:
			rd.Close()
			t.logger.Infow("received interrupt: exiting...", "interrupt", interrupt)
		}
	}()

	return t.listen(rd)
}

func (t *Tracer) listen(rd *ringbuf.Reader) error {
	var event sysoScEvent
	prevD := time.Now()
	d := time.Now()

	for {
		var ringbufFull bool
		if err := t.objects.ScEventsFullMap.Lookup(&rbfIndex, &ringbufFull); err != nil {
			return fmt.Errorf("failed to check if ringbuffer is full: %w", err)
		}

		if ringbufFull {
			return ErrRingbufFull
		}

		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			t.logger.Info("ringbuffer closed, exiting...")

			break
		}
		if err != nil {
			t.logger.Infow("read from bpf map failed", "err", err)

			continue
		}

		d = time.Now()

		if d.Sub(prevD) > BPFTimeoutDur {
			return ErrReadTimeout
		}

		prevD = d

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("failed to parse binary from bpf map: %w", err)
		}

		if err := t.Report(event); err != nil {
			return fmt.Errorf("failed to report event: %w", err)
		}
	}

	return nil
}

func (t *Tracer) Report(event sysoScEvent) error {
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

	stat := Stat{
		SyscallNr: event.SyscallNr,
		Library:   sharedLib,
		Pid:       event.Pid,
		Ppid:      event.Ppid,
		Timestamp: event.Timestamp,
	}

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

	return nil
}
