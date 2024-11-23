package main

import (
	"log"
	"os"

	"github.com/tcassar-diss/syso/syso"
	"go.uber.org/zap"
)

func v1() {
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

func v2() {
	prodLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get logger: %w", err)
	}

	logger := prodLogger.Sugar()

	tracer := syso.NewMtTracer(syso.Cfg{BatchSize: 1}, logger)

	if err := tracer.Trace("./main", "hello", "world"); err != nil {
		logger.Fatalw("failed to trace main", "err", err)
	}
}

func main() {
	v2()
}
