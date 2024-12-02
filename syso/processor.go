package syso

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Processor struct {
	logger *zap.SugaredLogger
	rb     *ringbuf.Reader
}

func NewProcessor(logger *zap.SugaredLogger, rb *ringbuf.Reader) *Processor {
	return &Processor{
		logger: logger,
		rb:     rb,
	}
}

func (p *Processor) Start(ctx context.Context) error {
	var group errgroup.Group

	// Closing eventChan is left to p.listen as it is the only method which writes to eventChan.
	eventChan := make(chan *sysoScEvent, 2048)

	group.Go(func() error {
		if err := p.listen(ctx, eventChan); err != nil {
			return fmt.Errorf("failed to listen to ring buffer: %w", err)
		}

		return nil
	})

	group.Go(func() error {
		p.consume(ctx, eventChan)
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

func (p *Processor) consume(ctx context.Context, eventChan chan *sysoScEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-eventChan:
		}
	}
}
