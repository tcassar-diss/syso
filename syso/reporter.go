package syso

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"

	"go.uber.org/zap"
)

var ErrCannotWriteStats = errors.New("cannot write stats to disk")

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
func NewMTReporter(logger *zap.SugaredLogger) (Reporter, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	info, err := os.Stat(path.Join(wd, "stats"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to check if ./stats exists: %w", err)
	}

	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir("./stats", 0o777); err != nil {
			return nil, fmt.Errorf("%w: couldn't make stats directory: %w", ErrCannotWriteStats, err)
		}
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("%w: non-directory file called stats present", ErrCannotWriteStats)
	}

	return &mtReporter{
		logger: logger,
		stats:  make(map[string]map[uint64]int),
	}, nil
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

	u.logger.Debugw("syscall from a new library", "library", stat.Library)
}

func (u *mtReporter) WriteMissed(filepath string, missed *MissedStats) error {
	u.logger.Infow("saving missed stats to disk", "path", filepath)
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
	u.logger.Infow("saving count stats", "path", filepath)

	u.mu.Lock()
	defer u.mu.Unlock()

	bts, err := json.Marshal(u.stats)
	if err != nil {
		return fmt.Errorf("failed to marshall stats: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		return fmt.Errorf("failed to save syscall stats: %w", err)
	}

	return nil
}
