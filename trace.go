package syso

import (
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"os"
	"os/exec"
)

var ErrNotElf = errors.New("not an elf")

type Stat struct {
	SyscallNr int
	Library   string
}

// Tracer gathers information about system call statistics
type Tracer interface {
	// Trace records all system calls for the given executable and its arguments
	Trace(binPath string, args ...string) error
	Stats() []Stat
}

func NewTracer(logger *zap.SugaredLogger, statsList []Stat) Tracer {
	return &tracer{
		logger: logger,
		stats:  statsList,
	}
}

type tracer struct {
	stats  []Stat
	logger *zap.SugaredLogger
}

func (t *tracer) Trace(binPath string, args ...string) error {
	pid := os.Getpid()

	t.logger.Infow("Getting current (go) process- PID", "PID", pid)

	// todo: write pid to ebpf map

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

	cmd := exec.Command(binPath, args...)

	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to launch application: %w", err)
	}
	defer cmd.Wait()

	// todo: listen to ebpf map

	return nil
}

func (t *tracer) Stats() []Stat {
	return t.stats
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
