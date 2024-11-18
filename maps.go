package syso

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

type MemMap struct {
	AddrStart uint64
	AddrEnd   uint64
	PathName  string
}

func (m *MemMap) contains(addr uint64) bool {
	return addr >= m.AddrStart && addr < m.AddrEnd
}

type ProcMaps struct {
	logger *zap.SugaredLogger
	files  map[int32]*os.File
	maps   map[int32][]*MemMap
}

func NewProcMaps(logger *zap.SugaredLogger) ProcMaps {
	return ProcMaps{
		logger: logger,
		files:  make(map[int32]*os.File),
		maps:   make(map[int32][]*MemMap),
	}
}

func (p ProcMaps) Close() error {
	for pid, f := range p.files {
		if err := f.Close(); err != nil {
			p.logger.Errorw("failed to close proc map file", "pid", pid, "err", err)
		}
	}

	return nil
}

// ByPID will return memory mappings for a given PID.
//
// ByPID will cache: to force a new lookup, use dirty=true.
func (p ProcMaps) ByPID(pid int32, dirty bool) ([]*MemMap, error) {
	var (
		f   *os.File
		ok  bool
		err error
	)

	f, ok = p.files[pid]
	if !ok || dirty {
		fp := fmt.Sprintf("/proc/%d/maps", pid)
		f, err = os.Open(fp)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", fp, err)
		}

		p.files[pid] = f

		p.logger.Infow("loading proc maps from filesystem", "pid", pid)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start of file")
	}

	scanner := bufio.NewScanner(f)

	c := 0

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) < 6 {
			continue
		}

		c++

		addrParts := strings.SplitN(fields[0], "-", 2)

		addrStart, err := strconv.ParseUint(addrParts[0], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse start of address range: %w", err)
		}

		addrEnd, err := strconv.ParseUint(addrParts[1], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse end of address range: %w", err)
		}

		p.maps[pid] = append(p.maps[pid], &MemMap{
			AddrStart: addrStart,
			AddrEnd:   addrEnd,
			PathName:  fields[len(fields)-1],
		})
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start of file")
	}

	p.logger.Infow("Loaded proc/[PID]/maps", "c", c)

	return p.maps[pid], nil
}

// AssignPC will assign a PC value to a shared object file.
//
// AssignPC relies on ByPID: pass dirty=true to force a new proc maps lookup.
func (p ProcMaps) AssignPC(pc uint64, pid int32, dirty bool) (string, error) {
	mmap, err := p.ByPID(pid, dirty)
	if err != nil {
		return "", fmt.Errorf("failed to load memory map: %w", err)
	}

	for _, m := range mmap {
		if !m.contains(pc) {
			continue
		}

		return m.PathName, nil
	}

	return "unmapped", nil
}
