package syso

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

const (
	ErrLim   = 50
	StatsDir = "./stats"
)

var (
	ErrNotElf          = errors.New("not an elf")
	ErrTooManyFailures = errors.New("failed to read from ringbuffer too many times in a row")
)

type Stat struct {
	SyscallNr uint64 `json:"syscall_nr,omitempty"`
	Library   string `json:"library,omitempty"`
	Pid       int32  `json:"pid,omitempty"`
	Ppid      int32  `json:"ppid,omitempty"`
	Timestamp uint64 `json:"timestamp,omitempty"`
}

// Tracer gathers information about system call statistics by dynamic execution
type Tracer interface {
	// Trace records all system calls for the given executable and its arguments
	Trace(binPath string, args ...string) error
	DumpStats(fp string) error
}

func NewTracer(logger *zap.SugaredLogger, statsList []Stat) Tracer {
	return &tracer{
		logger: logger,
		stats:  statsList,
		maps:   NewProcMaps(logger),
	}
}

type tracer struct {
	logger  *zap.SugaredLogger
	maps    ProcMaps
	stopper chan os.Signal
	stats   []Stat
}

func (t *tracer) Trace(binPath string, args ...string) error {
	pid := os.Getpid()
	tgid := os.Getgid()

	t.logger.Infow("Getting current (go) process", "pid", pid, "tgid", tgid)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to clear memlock: %w", err)
	}

	var objs sysoObjects
	if err := loadSysoObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load bpf objects: %w", err)
	}

	//err := objs.PpidMap.Put(1, pid)
	//if err != nil {
	//	return fmt.Errorf("failed to write pid into ppid_map: %w", err)
	//}

	isElf, err := t.isElf(binPath)
	if err != nil {
		return fmt.Errorf("failed to check if file is an ELF: %w", err)
	}

	if !isElf {
		return ErrNotElf
	}

	//// todo: do some proper path validation
	//if binPath[:2] != "./" || binPath[:1] != "/" {
	//	binPath = "./" + binPath
	//}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.sysoPrograms.RawTpSysEnter,
	})
	if err != nil {
		return fmt.Errorf("failed to attack to raw tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.ScEventsMap)
	if err != nil {
		return fmt.Errorf("failed to get reader to sc_events_map: %w", err)
	}
	defer rd.Close()

	if t.stopper == nil {
		t.stopper = make(chan os.Signal, 1)
	}
	signal.Notify(t.stopper, os.Interrupt, syscall.SIGTERM)

	cmd := exec.Command(binPath, args...)

	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("executable failed to start: %w", err)
	}
	defer cmd.Wait()

	if err := t.listen(rd); err != nil {
		return fmt.Errorf("listening to ring buffer failed: %w", err)
	}

	if err := t.DumpStats(fmt.Sprintf("%s-stats.json", binPath)); err != nil {
		return fmt.Errorf("failed to save stats: %w", err)
	}

	return nil
}

func (t *tracer) DumpStats(fp string) error {
	t.logger.Infow("writing stats to file", "fp", fp)

	bts, err := json.Marshal(t.stats)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(fp, bts, 0x777); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

func (t *tracer) isElf(fp string) (bool, error) {
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

func (t *tracer) listen(rd *ringbuf.Reader) error {
	var event sysoScEvent

	follow := make(map[int32]bool)

	pid := os.Getpid()
	failures := 0

	follow[int32(pid)] = true

	for {
		go func() {
			<-t.stopper

			rd.Close()
		}()

		if failures > ErrLim {
			return fmt.Errorf("%w: surpassed %d errors", ErrTooManyFailures, ErrLim)
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				t.logger.Infow("ring buffer closed; exiting...")

				failures++

				break
			}

			t.logger.Errorw("failed to read from record", "err", err)

			failures++

			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			t.logger.Errorw("failed to read from ringbuffer", "err", err)

			failures++

			continue
		}

		failures = 0

		if _, ok := follow[event.Ppid]; !ok {
			continue
		}

		follow[event.Pid] = true

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

		t.stats = append(t.stats, Stat{
			SyscallNr: event.SyscallNr,
			Library:   sharedLib,
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Timestamp: event.Timestamp,
		})
	}

	return nil
}
