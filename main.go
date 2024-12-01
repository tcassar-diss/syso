package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/tcassar-diss/syso/syso"
	"go.uber.org/zap"
)

func main() {
	prodLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get logger: %w", err)
	}

	logger := prodLogger.Sugar()

	wd, err := os.Getwd()
	if err != nil {
		logger.Fatalw("failed to get working directory", "err", err)
	}

	maps := syso.NewProcMaps(logger)

	executable := os.Args[1]
	args := os.Args[2:]

	_, execName := path.Split(executable)

	statsFp := path.Join(wd, "stats", fmt.Sprintf("%s-stats.json", execName))

	f, err := os.Create(statsFp)
	if err != nil {
		log.Fatalf("failed to create output file")
	}
	defer f.Close()

	reporter := syso.NewUntimedReporter(logger, f)

	tracer, err := syso.NewTracer(logger, &maps, reporter)
	if err != nil {
		logger.Fatalw("failed to create tracer", "err", err)
	}

	ctx := context.Background()

	err = tracer.Trace(ctx, executable, args...)
	if err != nil {
		logger.Fatalw("failed to trace", "executable", executable, "err", err)
	}
}
