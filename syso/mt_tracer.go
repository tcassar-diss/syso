package syso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

var (
	ErrBPFInitialised     = errors.New("ebpf backend already initialised")
	ErrInvalidTraceFormat = errors.New("invalid input format")
)

type Cfg struct {
	// ReadFailureLimit is the number of times in a row which reads from kernel space can fail
	// without halting the program.
	ReadFailureLimit int

	// ReportFailureLimit is the number of times in a row which logging a statistic to stdout can fail without halting
	// the program.
	ReportFailureLimit int

	// BatchSize is the number of stats stored before being printed to stdout.
	BatchSize int
}

type mtTracer struct {
	cfg    Cfg
	logger *zap.SugaredLogger
	objs   sysoObjects
}

func NewMtTracer(cfg Cfg, logger *zap.SugaredLogger) Tracer {
	return &mtTracer{cfg: cfg, logger: logger}
}

func (t *mtTracer) Trace(binPath string, args ...string) error {
	t.logger.Infow("starting trace...", "executable", binPath, "args", args)

	isELF, err := t.isElf(binPath)
	if err != nil {
		return fmt.Errorf("failed to check if input is an executable: %w", err)
	}

	if !isELF {
		return fmt.Errorf("executable is not an elf: %w", ErrInvalidTraceFormat)
	}

	tp, err := t.loadBPF()
	if err != nil {
		return fmt.Errorf("failed to initialise ebpf backend: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(t.objs.ScEventsMap)
	if err != nil {
		return fmt.Errorf("failed to get a reader to sc_events_map: %w", err)
	}
	defer rd.Close()

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rawEventChan := make(chan sysoScEvent, 1024)
	defer close(rawEventChan)

	errorChan := make(chan error)
	defer close(errorChan)

	go func() {
		<-errorChan

		t.logger.Errorw("failed to process event from bpf backend", "err", err)

		cancel()

		return
	}()

	statsChan := make(chan []Stat)
	defer close(statsChan)

	wg.Add(1)
	go func() {
		defer wg.Done()
		t.listen(ctx, rawEventChan, errorChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		t.batch(ctx, rawEventChan, statsChan, errorChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		t.report(ctx, statsChan, errorChan)
	}()

	wg.Wait()

	return nil
}

func (t *mtTracer) DumpStats(fp string) error {
	return nil
}

// loadBPF will initialise the ebpf backend and return a link to which the ebpf program is attached.
func (t *mtTracer) loadBPF() (link.Link, error) {
	t.logger.Info("initialising ebpf backend")

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("are you root? failed to remove memlock: %w", err)
	}

	if err := loadSysoObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load syso objects: %w", err)
	}

	if err := t.objs.FollowPidMap.Put(int32(os.Getpid()), true); err != nil {
		return nil, fmt.Errorf("failed to pass current PID to bpf: %w", err)
	}

	return link.AttachRawTracepoint(
		link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: t.objs.sysoPrograms.RawTpSysEnter,
		})
}

func (t *mtTracer) isElf(fp string) (bool, error) {
	f, err := os.Open(fp)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}

	bts, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return false, fmt.Errorf("failed to parse first 32 bytes of executable: %w", err)
	}

	return "ELF" == string(bts[1:4]), nil
}

func (t *mtTracer) listen(ctx context.Context, rawEventChan chan sysoScEvent, errChan chan error) {
	t.logger.Infow("listening to bpf backend")

	rawEventChan <- sysoScEvent{
		Pid:       1,
		Ppid:      1,
		Timestamp: 1,
		SyscallNr: 1,
		Pc:        1,
		Dirty:     false,
	}
}

func (t *mtTracer) batch(
	ctx context.Context,
	rawEventChan chan sysoScEvent,
	statsChan chan []Stat,
	errChan chan error,
) {
	var (
		event sysoScEvent
		batch []Stat
	)

	for {
		select {
		case <-ctx.Done():
			t.logger.Infow("context cancelled: flushing batch, and quitting...")
			statsChan <- batch

			return
		case event = <-rawEventChan:
		}

		batch = append(batch, Stat{
			SyscallNr: event.SyscallNr,
			Library:   "tbd",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Timestamp: event.Timestamp,
		})

		if len(batch) < t.cfg.BatchSize {
			continue
		}

		statsChan <- batch

		// reset batch while keeping underlying memory
		batch = batch[:0]
	}
}

func (t *mtTracer) report(ctx context.Context, statsChan chan []Stat, errChan chan error) {
	var stats []Stat

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("report context cancelled, quitting...")

			return
		case stats = <-statsChan:
		}

		bts, err := json.Marshal(stats)
		if err != nil {
			t.logger.Errorw("failed to output stat", "err", err)

			errChan <- err
		}

		// string slicing removes leading/trailing square brackets
		fmt.Printf("%s,", string(bts)[1:len(string(bts))-1])
	}
}
