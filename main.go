package main

import (
	"context"
	"github.com/tcassar-diss/syso/internal/procmaps"
	"log"
	"os"

	"github.com/tcassar-diss/syso/internal/naive"
	"go.uber.org/zap"
)

func main() {
	prodLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get logger: %w", err)
	}

	logger := prodLogger.Sugar()

	maps := procmaps.NewProcMaps(logger)

	executable := os.Args[1]
	args := os.Args[2:]

	reporter := naive.NewMTReporter(logger)

	tracer, err := naive.NewTracer(logger, &maps, reporter)
	if err != nil {
		logger.Fatalw("failed to create tracer", "err", err)
	}

	ctx := context.Background()

	err = tracer.Trace(ctx, executable, args...)
	if err != nil {
		logger.Fatalw("failed to trace", "executable", executable, "err", err)
	}

	if err := reporter.WriteFile("/app/stats/counts.json"); err != nil {
		logger.Fatalw("failed to write stats", "err", err)
	}
}
