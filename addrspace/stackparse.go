package addrspace

import (
	"fmt"

	"go.uber.org/zap"
)

const LibcPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"

// StackParser will use stack traces to identify the library responsible
// for calling libc syscall wrapper.
type StackParser struct {
	logger *zap.SugaredLogger
	maps   *ProcMaps
	seen   bool
}

func NewStackParser(logger *zap.SugaredLogger, maps *ProcMaps) *StackParser {
	return &StackParser{
		logger: logger,
		maps:   maps,
	}
}

// AssignPC assigns a trace of return pointers to a shared library by PID.
func (s *StackParser) AssignPC(pid int32, trace [64]uint64, dirty bool) (string, error) {
	if trace[len(trace)-1] != 0 {
		s.logger.Warn("deepest frame non-0 => stacktrace may not be deep enough", "pid", pid)
	}

	var (
		lib string
		err error
	)

	for _, rp := range trace {
		if rp == 0 {
			break
		}

		lib, err = s.maps.AssignPC(rp, pid, dirty)
		if err != nil {
			s.logger.Warnw("failed to assign return pointer to memory map",
				"pid", pid,
				"rp", rp,
				"err", err,
			)

			// try to keep going up the stack - see if we end up somewhere that we expect
			// todo: decide if this is the correct intended behaviour

			continue
		}

		if lib == LibcPath {
			continue
		}

		return lib, nil
	}

	if lib != LibcPath {
		return "A", fmt.Errorf("failed to assign syscall site to library: %w", ErrNoMappingExists)
	}

	return LibcPath, nil
}
