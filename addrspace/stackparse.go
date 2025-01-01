package addrspace

import (
	"errors"
	"fmt"

	"go.uber.org/zap"
)

const LibcPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"

var ErrNoLibc = errors.New("no libc in process address space")

type libcRange struct {
	start, end uint64
}

func (l *libcRange) contains(rp uint64) bool {
	return rp >= l.start && rp < l.end
}

// StackParser will use stack traces to identify the library responsible
// for calling libc syscall wrapper.
type StackParser struct {
	logger     *zap.SugaredLogger
	maps       *ProcMaps
	libcRanges map[int32]*libcRange
}

func NewStackParser(logger *zap.SugaredLogger, maps *ProcMaps) *StackParser {
	return &StackParser{
		logger:     logger,
		maps:       maps,
		libcRanges: make(map[int32]*libcRange),
	}
}

// AssignPC assigns a trace of return pointers to a shared library by PID.
func (s *StackParser) AssignPC(pid int32, trace []uint64, dirty bool) (string, error) {
	rge, err := s.loadLibcRange(pid, dirty)
	if err != nil {
		// todo: would it be a suitable fallback to assign top of
		// stack with procmaps in this case? maybe better to handle one level higher.
		return "", fmt.Errorf("failed to load libc address range: %w", err)
	}

	callsiteRp := uint64(0)

	for _, rp := range trace {
		if rge.contains(rp) {
			continue
		}

		callsiteRp = rp
		break
	}

	if callsiteRp == 0 {
		s.logger.Warn("no non-libc ")
		return LibcPath, nil
	}

	lib, err := s.maps.AssignPC(callsiteRp, pid, dirty)
	if err != nil {
		return "", fmt.Errorf("failed to assign library to first non-libc rp: %w", err)
	}

	return lib, nil
}

func (s *StackParser) loadLibcRange(pid int32, dirty bool) (*libcRange, error) {
	var rge *libcRange

	rge, ok := s.libcRanges[pid]
	if ok && !dirty {
		return rge, nil
	}

	mmaps, err := s.maps.ReadAddrSpace(pid, dirty)
	if err != nil {
		return nil, fmt.Errorf("couldn't load address space: %w", err)
	}

	for _, m := range mmaps {
		if m.PathName != LibcPath {
			continue
		}

		return &libcRange{m.AddrStart, m.AddrEnd}, nil
	}

	return nil, ErrNoLibc
}
