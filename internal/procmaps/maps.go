package procmaps

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

type MemMap struct {
	AddrStart uint64
	AddrEnd   uint64
	Offset    uint64
	PathName  string
}

func (m *MemMap) contains(addr uint64) bool {
	return addr >= m.AddrStart && addr < m.AddrEnd
}

// ProcMaps provides a thread safe way to read the virtual address space of a process.
type ProcMaps struct {
	logger *zap.SugaredLogger
	maps   map[int32][]*MemMap
	mu     sync.Mutex
}

func NewProcMaps(logger *zap.SugaredLogger) ProcMaps {
	return ProcMaps{
		logger: logger,
		maps:   make(map[int32][]*MemMap),
	}
}

// ReadAddrSpace will return memory mappings for a given PID.
//
// ReadAddrSpace will cache: to force a new lookup, use dirty=true.
func (p *ProcMaps) ReadAddrSpace(pid int32, dirty bool) ([]*MemMap, error) {
	var (
		maps []*MemMap
		err  error
	)

	p.mu.Lock()
	maps, ok := p.maps[pid]
	p.mu.Unlock()

	if dirty || !ok {
		p.logger.Infow("reading address space", "pid", pid)

		maps, err = p.readAddrSpace(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to read process %d's address space: %w", pid, err)
		}

		p.mu.Lock()
		p.maps[pid] = maps
		p.mu.Unlock()
	}

	return maps, nil
}

func (p *ProcMaps) readAddrSpace(pid int32) ([]*MemMap, error) {
	fp := fmt.Sprintf("/proc/%d/maps", pid)

	f, err := os.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fp, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var maps []*MemMap

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) < 6 {
			continue
		}

		addrParts := strings.SplitN(fields[0], "-", 2)

		addrStart, err := strconv.ParseUint(addrParts[0], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse start of address range: %w", err)
		}

		addrEnd, err := strconv.ParseUint(addrParts[1], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse end of address range: %w", err)
		}

		offset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse offset: %w", err)
		}

		maps = append(maps, &MemMap{
			AddrStart: addrStart,
			AddrEnd:   addrEnd,
			Offset:    offset,
			PathName:  fields[len(fields)-1],
		})
	}

	if maps == nil {
		p.logger.Warnw("nothing in /proc/pid/maps", "pid", pid)
	}

	return maps, nil
}

// AssignPC will assign a PC value to a shared object file.
//
// AssignPC relies on ReadAddrSpace: pass dirty=true to force a new proc maps lookup.
func (p *ProcMaps) AssignPC(pc uint64, pid int32, dirty bool) (string, error) {
	mmap, err := p.ReadAddrSpace(pid, dirty)
	if err != nil {
		return "", fmt.Errorf("failed to load memory map: %w", err)
	}

	if len(mmap) == 0 {
		p.logger.Warnw("empty memory map", "pid", pid, "pc", pc, "dirty", dirty)
	}

	for _, m := range mmap {
		if !m.contains(pc) {
			continue
		}

		return m.PathName, nil
	}

	// if there was no mapping associated with [stack], [heap], or a shared library,
	// the call must have come from an anonymously mapped space
	return "anonymous", nil
}
