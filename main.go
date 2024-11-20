package main

import (
	"log"
	"os"

	"github.com/tcassar-diss/syso/syso"
	"go.uber.org/zap"
)

func main() {
	prodLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get logger: %w", err)
	}

	logger := prodLogger.Sugar()

	var stats []syso.Stat

	tracer := syso.NewTracer(logger, stats)

	err = tracer.Trace(os.Args[1], os.Args[2:]...)
	if err != nil {
		logger.Errorw("failed to trace program", "err", err)
	}
}
