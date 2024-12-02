package syso

import (
	"encoding/json"
	"fmt"
	"io"

	"go.uber.org/zap"
)

// Reporter reports syso stats in an efficient manner
type Reporter struct {
	logger *zap.SugaredLogger
	output io.Writer
}

func NewReporter(logger *zap.SugaredLogger, output io.Writer) *Reporter {
	return &Reporter{
		logger: logger,
		output: output,
	}
}

func (r *Reporter) ReportMissed(missed *MissedStats) error {
	// as json for now
	bts, err := json.Marshal(missed)
	if err != nil {
		return fmt.Errorf("failed to marshall to json: %w", err)
	}

	n, err := r.output.Write(bts)
	if err != nil {
		return fmt.Errorf("failed to write to output stream: %w", err)
	}

	if n < len(bts) {
		return fmt.Errorf(
			"failed to write to output stream: wrote %dB, expected %dB: %w",
			n,
			len(bts),
			io.ErrShortWrite,
		)
	}

	return nil
}
