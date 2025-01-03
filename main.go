package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/tcassar-diss/syso/addrspace"
	"github.com/tcassar-diss/syso/syso"
	"go.uber.org/zap"
)

func main() {
	prodLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get logger: %v", err)
	}

	logger := prodLogger.Sugar()

	maps := addrspace.NewProcMaps(logger)
	stackparser := addrspace.NewStackParser(logger, &maps)

	executable := os.Args[1]
	args := os.Args[2:]

	reporter := syso.NewMTReporter(logger)

	// todo: timeout and jobs as cli arguments
	tracer, err := syso.NewTracer(logger, stackparser, reporter, 6000*time.Second, 1)
	if err != nil {
		logger.Fatalw("failed to create tracer", "err", err)
	}

	ctx := context.Background()

	err = tracer.Trace(ctx, executable, args...)
	if err != nil {
		logger.Fatalw("failed to trace", "executable", executable, "err", err)
	}
}
