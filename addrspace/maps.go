package addrspace

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"

	"go.uber.org/zap"
)

var ErrPMEntryInvalid = errors.New("procmaps line invalid")

var PMRegex = regexp.MustCompile(`^([a-z0-9]+)-([a-z0-9]+)\s[rwxsp-]{4}\s([0-9a-f]{8})\s\d{2}:\d{2}\s\d+\s+(.*)$`)

type MemMap struct {
	AddrStart uint64
	AddrEnd   uint64
	PathName  string
}

func (m *MemMap) contains(addr uint64) bool {
	return addr >= m.AddrStart && addr < m.AddrEnd
}

// ProcMaps provides a thread safe way to read the virtual address space of a process.
type ProcMaps struct {
	logger      *zap.SugaredLogger
	maps        map[int32][]*MemMap
	mu          sync.Mutex
	pathbuilder func(int32) string
}

// NewProcMaps is configured to look in /proc/pid/maps for processes' address spaces.
func NewProcMaps(logger *zap.SugaredLogger) ProcMaps {
	return ProcMaps{
		logger:      logger,
		maps:        make(map[int32][]*MemMap),
		pathbuilder: func(pid int32) string { return fmt.Sprintf("/proc/%d/maps", pid) },
	}
}

// NewTestProcMaps is configured with a Nop logger and a pathbuilder. pathbuilder specifies
// where to look for address spaces to read.
func NewTestProcMaps(pathbuilder func(int32) string) ProcMaps {
	return ProcMaps{
		logger:      zap.NewNop().Sugar(),
		maps:        make(map[int32][]*MemMap),
		pathbuilder: pathbuilder,
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

func (p *ProcMaps) parseLine(l string) (*MemMap, error) {
	res := PMRegex.FindAllStringSubmatch(l, -1)

	if len(res) != 1 || len(res[0]) != 5 {
		return nil, fmt.Errorf("%w: regex didn't match 4 expected fields", ErrPMEntryInvalid)
	}

	start, err := strconv.ParseUint(res[0][1], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address start %s: %w", res[0], err)
	}

	end, err := strconv.ParseUint(res[0][2], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address end %s: %w", res[0], err)
	}

	path := string(res[0][4])

	return &MemMap{
		AddrStart: start,
		AddrEnd:   end,
		PathName:  path,
	}, nil
}

func (p *ProcMaps) readAddrSpace(pid int32) ([]*MemMap, error) {
	fp := p.pathbuilder(pid)

	f, err := os.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fp, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	mmaps := make(map[string]*MemMap)

	for scanner.Scan() {
		l := scanner.Text()

		if l == "" || l == "\n" {
			continue
		}

		addrs, err := p.parseLine(l)
		if errors.Is(err, ErrPMEntryInvalid) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed to parse procmaps line: %w", err)
		}

		existing, ok := mmaps[addrs.PathName]
		if !ok {
			mmaps[addrs.PathName] = addrs
			continue
		}

		existing.AddrStart = min(existing.AddrStart, addrs.AddrStart)
		existing.AddrEnd = max(existing.AddrEnd, addrs.AddrEnd)
	}

	if len(mmaps) == 0 {
		p.logger.Warnw("nothing in /proc/pid/maps", "pid", pid)
	}

	return slices.Collect(maps.Values(mmaps)), nil
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
