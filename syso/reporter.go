package syso

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
)

type Reporter interface {
	Report(stat *Stat)
	WriteMissed(filepath string, missed *MissedStats) error
	WriteFile(filepath string) error
}

type mtReporter struct {
	logger *zap.SugaredLogger
	// stats is a map from library -> syscall_nr -> count
	stats map[string]map[uint64]int
	mu    sync.Mutex
}

// NewMTReporter is a thread safe reporter that ignores timestamps.
//
// The reporter associates a library with a syscall number and a count.
func NewMTReporter(logger *zap.SugaredLogger) Reporter {
	return &mtReporter{
		logger: logger,
		stats:  make(map[string]map[uint64]int),
	}
}

func (u *mtReporter) Report(stat *Stat) {
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

func (u *mtReporter) WriteMissed(filepath string, missed *MissedStats) error {
	bts, err := json.Marshal(missed)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}

func (u *mtReporter) WriteFile(filepath string) error {
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

type completeReporter struct {
	logger *zap.SugaredLogger
	stats  []*Stat
	mu     sync.Mutex
}

// NewCompleteReporter returns a reporter which writes all stats
func NewCompleteReporter(logger *zap.SugaredLogger) Reporter {
	return &completeReporter{logger: logger}
}

func (c *completeReporter) Report(stat *Stat) {
	c.mu.Lock()
	c.stats = append(c.stats, stat)
	c.mu.Unlock()
}

func (c *completeReporter) WriteMissed(filepath string, missed *MissedStats) error {
	bts, err := json.Marshal(missed)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}

func (c *completeReporter) WriteFile(filepath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.Infow("saving count stats")

	bts, err := json.Marshal(c.stats)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}
