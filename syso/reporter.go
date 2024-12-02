package syso

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"go.uber.org/zap"
)

type Reporter interface {
	Report(stat *Stat)
	WriteMissed(filepath string, missed *MissedStats) error
	WriteFile(filepath string) error
}

type untimedReporter struct {
	logger *zap.SugaredLogger
	output io.Writer
	// stats is a map from library -> syscall_nr -> count
	stats map[string]map[uint64]int
	mu    sync.Mutex
}

// NewUntimedReporter is a thread safe reporter that ignores timestamps.
//
// The reporter associates a library with a syscall number and a count.
func NewUntimedReporter(logger *zap.SugaredLogger, output io.Writer) Reporter {
	return &untimedReporter{
		logger: logger,
		output: output,
		stats:  make(map[string]map[uint64]int),
	}
}

func (u *untimedReporter) Report(stat *Stat) {
	u.mu.Lock()
	_, ok := u.stats[stat.Library]

	if ok {
		u.stats[stat.Library][stat.SyscallNr]++
		u.mu.Unlock()
		return
	}

	u.stats[stat.Library] = make(map[uint64]int)
	u.stats[stat.Library][stat.SyscallNr]++

	u.mu.Unlock()

	u.logger.Infow("syscall from a new library", "library", stat.Library)
}

func (u *untimedReporter) WriteMissed(filepath string, missed *MissedStats) error {
	bts, err := json.Marshal(missed)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}

func (u *untimedReporter) WriteFile(filepath string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.logger.Infow("saving count stats")

	bts, err := json.Marshal(u.stats)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}
