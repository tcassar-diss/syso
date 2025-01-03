package syso

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/tcassar-diss/syso/addrspace"
	"go.uber.org/zap"
)

type Tracer struct {
	logger      *zap.SugaredLogger
	processor   *Processor
	reporter    Reporter
	stackparser *addrspace.StackParser
	objects     *sysoObjects
	timeout     time.Duration
	jobs        int
}

func NewTracer(
	logger *zap.SugaredLogger,
	stackparser *addrspace.StackParser,
	reporter Reporter,
	timeout time.Duration,
	jobs int,
) (*Tracer, error) {
	t := Tracer{
		logger:      logger,
		stackparser: stackparser,
		objects:     &sysoObjects{},
		reporter:    reporter,
		timeout:     timeout,
		jobs:        jobs,
	}

	if err := loadSysoObjects(t.objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load bpf objects: %w", err)
	}

	return &t, nil
}

// Trace will log all system calls that an executable makes, writing them to ./stats directory.
func (t *Tracer) Trace(ctx context.Context, executable string, args ...string) error {
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

	t.processor = NewProcessor(t.logger, rd, t.stackparser, t.reporter, &ProcessorCgf{
		workers:         1,
		eventChanBuffer: 1024,
		statsChanBuffer: 1024,
	})

	cmd := exec.Command(executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executable: %w", err)
	}
	defer cmd.Wait()

	ctx, cancel := context.WithTimeout(ctx, t.timeout)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer close(stopper)

	go func() {
		select {
		case <-ctx.Done():
			rd.Close()
			cancel()
			t.logger.Infow("timeout hit, exiting...")
		case <-stopper:
			rd.Close()
			cancel()
			t.logger.Infow("interrupt received, exiting...")
		}
	}()

	if err := t.processor.Start(ctx); err != nil {
		return fmt.Errorf("failed to process stats from kernel: %w", err)
	}

	missed, err := t.readMissedMap()
	if err != nil {
		return fmt.Errorf("failed to read missed stats map: %w", err)
	}

	ff := t.readForkFollow()
	t.logger.Infow("fork follow", "curr", os.Getpid(), "pids", ff)

	if err := t.reporter.WriteMissed("./stats/missed.json", missed); err != nil {
		return fmt.Errorf("failed to report missed stats: %w", err)
	}

	if err := t.reporter.WriteFile("./stats/counts.json"); err != nil {
		return fmt.Errorf("failed to report syscall counts: %w", err)
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

func (t *Tracer) initMissedMap() error {
	zero := uint64(0)

	// this is okay in >=go1.22
	// see https://go.dev/wiki/LoopvarExperiment
	for i := int32(0); i < nSysoFailureTypes; i++ {
		if err := t.objects.ErrMap.Put(&i, &zero); err != nil {
			return fmt.Errorf("failed to initialise errmap %d to zero: %w", i, err)
		}
	}

	return nil
}

func (t *Tracer) readMissedMap() (*MissedStats, error) {
	var (
		rbFull         uint64
		getTaskFailed  uint64
		parentFailed   uint64
		ptRegsFailed   uint64
		ignoreWrongPID uint64
		all            uint64
		relevant       uint64
		emptyst        uint64
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

	i = sysoFailureTypeIGNORE_WRONG_PID
	if err := t.objects.ErrMap.Lookup(&i, &ignoreWrongPID); err != nil {
		return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
	}

	i = sysoFailureTypeALL_SYSCALLS
	if err := t.objects.ErrMap.Lookup(&i, &all); err != nil {
		return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
	}

	i = sysoFailureTypeGET_TASK_FAILED
	if err := t.objects.ErrMap.Lookup(&i, &getTaskFailed); err != nil {
		return nil, fmt.Errorf("failed to read get_task_failed errors: %w", err)
	}

	i = sysoFailureTypeEMPTY_STACKTRACE
	if err := t.objects.ErrMap.Lookup(&i, &emptyst); err != nil {
		return nil, fmt.Errorf("failed to read empty-stacktrace errors: %w", err)
	}

	i = sysoFailureTypeRELEVANT_SYSCALLS
	if err := t.objects.ErrMap.Lookup(&i, &relevant); err != nil {
		return nil, fmt.Errorf("failed to read procstart errors: %w", err)
	}

	t.logger.Infow(
		"missed syscalls",
		"ringbuf-full", rbFull,
		"get-current-task-failed", getTaskFailed,
		"get-parent-failed", parentFailed,
		"get-pt-regs-failed", ptRegsFailed,
		"follow-ignore-pid", ignoreWrongPID,
		"empty-stack-trace", emptyst,
		"procstart", relevant,
		"all", all,
	)

	return &MissedStats{
		RingBufFull:          rbFull,
		GetParentFailed:      parentFailed,
		GetCurrentTaskFailed: getTaskFailed,
		GetPTRegsFailed:      ptRegsFailed,
		IgnorePID:            ignoreWrongPID,
		AllSyscalls:          all,
		RelevantSyscalls:     relevant,
	}, nil
}

func (t *Tracer) readForkFollow() []int32 {
	ff := make([]int32, 0)

	iter := t.objects.FollowPidMap.Iterate()
	for {
		var (
			pid  int32
			v    bool
			next bool
		)

		next = iter.Next(&pid, &v)
		ff = append(ff, pid)
		if !next {
			break
		}
	}

	return ff
}
