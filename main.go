package main

import (
	"context"
	"errors"
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
	defer maps.Close()

	executable := os.Args[1]
	args := os.Args[2:]

	_, execName := path.Split(executable)

	statsFp := path.Join(wd, "stats", fmt.Sprintf("%s-stats.json", execName))

	f, err := os.Create(statsFp)
	if err != nil {
		log.Fatalf("failed to create output file")
	}
	defer f.Close()

	tracer, err := syso.NewTracer(logger, f, &maps)
	if err != nil {
		logger.Fatalw("failed to create tracer", "err", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = tracer.Trace(ctx, executable, args...)
	if errors.Is(err, syso.ErrReadTimeout) {
		logger.Infow("quit after timeout, all done!")
	} else if err != nil {
		logger.Fatalw("failed to trace", "executable", executable, "err", err)
	}
}
