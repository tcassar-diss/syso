package syso

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Libs struct {
	logger    *zap.SugaredLogger
	libraries map[string]int
	mu        sync.Mutex
}

func NewLibs(logger *zap.SugaredLogger) *Libs {
	return &Libs{
		logger:    logger,
		libraries: make(map[string]int),
	}
}

func (l *Libs) Add(lib string) {
	l.mu.Lock()
	_, ok := l.libraries[lib]
	l.mu.Unlock()

	if ok {
		l.mu.Lock()
		l.libraries[lib]++
		l.mu.Unlock()
		return
	}

	l.logger.Infow("new library found", "library", lib)

	l.mu.Lock()
	l.libraries[lib] = 1
	l.mu.Unlock()
}

func (l *Libs) Dump() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.libraries
}

func (l *Libs) WriteFile(filepath string) error {
	bts, err := json.Marshal(l.Dump())
	if err != nil {
		return fmt.Errorf("failed to marshall libraries: %w", err)
	}

	if err := os.WriteFile(filepath, bts, 0o777); err != nil {
		l.logger.Errorw("library dump failed", "err", err)

		return fmt.Errorf("failed to dump libaries to file: %w", err)
	}

	return nil
}

type Processor struct {
	logger *zap.SugaredLogger
	rb     *ringbuf.Reader
	maps   *ProcMaps
	libs   *Libs
}

func NewProcessor(logger *zap.SugaredLogger, rb *ringbuf.Reader, maps *ProcMaps) *Processor {
	return &Processor{
		logger: logger,
		rb:     rb,
		maps:   maps,
		libs:   NewLibs(logger),
	}
}

func (p *Processor) Start(ctx context.Context) error {
	var group errgroup.Group

	// Closing eventChan is left to p.listen as it is the only method which writes to eventChan.
	eventChan := make(chan *sysoScEvent, 2048)
	statsChan := make(chan *Stat, 2048)

	group.Go(func() error {
		<-ctx.Done()
		close(statsChan)
		return nil
	})

	group.Go(func() error {
		return p.report(ctx, statsChan)
	})

	for i := 0; i < 1; i++ {
		group.Go(func() error {
			if err := p.consume(ctx, eventChan, statsChan); err != nil {
				return fmt.Errorf("failed to consume stats: %w", err)
			}
			return nil
		})
	}

	group.Go(func() error {
		if err := p.listen(ctx, eventChan); err != nil {
			return fmt.Errorf("failed to listen to ring buffer: %w", err)
		}

		return nil
	})

	if err := group.Wait(); err != nil {
		return fmt.Errorf("failed while processing stats: %w", err)
	}

	return nil
}

func (p *Processor) listen(ctx context.Context, eventChan chan<- *sysoScEvent) error {
	for {
		select {
		case <-ctx.Done():
			close(eventChan)
			return nil
		default:
		}

		record, err := p.rb.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			p.logger.Info("ringbuffer closed, exiting...")

			return nil
		} else if err != nil {
			return fmt.Errorf("failed to read from ringbuffer: %w", err)
		}

		var event sysoScEvent

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("failed to parse binary from bpf map: %w", err)
		}

		eventChan <- &event
	}
}

func (p *Processor) consume(ctx context.Context, eventChan <-chan *sysoScEvent, statsChan chan<- *Stat) error {
	var event *sysoScEvent

	for {
		select {
		case <-ctx.Done():
			return nil
		case event = <-eventChan:
		}

		library, err := p.maps.AssignPC(event.Pc, event.Pid, event.Dirty)
		if err != nil {
			return fmt.Errorf("failed to assign libary to syscall: %w", err)
		}

		statsChan <- &Stat{
			SyscallNr: event.SyscallNr,
			Library:   library,
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Timestamp: event.Timestamp,
		}
	}
}

func (p *Processor) report(ctx context.Context, statsChan <-chan *Stat) error {
	for {
		select {
		case <-ctx.Done():
			p.logger.Infow("found libraries", "libs", p.libs.Dump())
			return p.libs.WriteFile("/app/stats/libraries")
		case s := <-statsChan:
			p.libs.Add(s.Library)
		}
	}
}
