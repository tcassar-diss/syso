package naive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/tcassar-diss/syso/internal/procmaps"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type ProcessorCgf struct {
	workers         int
	eventChanBuffer int
	statsChanBuffer int
}

type Processor struct {
	logger   *zap.SugaredLogger
	rb       *ringbuf.Reader
	maps     *procmaps.ProcMaps
	reporter Reporter
	cfg      *ProcessorCgf
}

func NewProcessor(
	logger *zap.SugaredLogger,
	rb *ringbuf.Reader,
	maps *procmaps.ProcMaps,
	reporter Reporter,
	cfg *ProcessorCgf,
) *Processor {
	if cfg == nil {
		cfg = &ProcessorCgf{
			workers:         16,
			eventChanBuffer: 1024,
			statsChanBuffer: 1024,
		}
	}

	return &Processor{
		logger:   logger,
		rb:       rb,
		maps:     maps,
		reporter: reporter,
		cfg:      cfg,
	}
}

func (p *Processor) Start(ctx context.Context) error {
	var group errgroup.Group

	// Closing eventChan is left to p.listen as it is the only method which writes to eventChan.
	eventChan := make(chan *sysoScEvent, p.cfg.eventChanBuffer)
	statsChan := make(chan *Stat, p.cfg.statsChanBuffer)
	defer close(statsChan)

	group.Go(func() error {
		return p.report(ctx, statsChan)
	})

	for i := 0; i < p.cfg.workers; i++ {
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
			return nil
		case stat := <-statsChan:
			p.reporter.Report(stat)
		}
	}
}
