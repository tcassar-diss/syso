package main

import (
	"context"
	"fmt"
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
	defer logger.Sync()

	maps := addrspace.NewProcMaps(logger)
	stackparser := addrspace.NewStackParser(logger, &maps)

	if len(os.Args) < 2 {
		fmt.Println("Failed to run: please provide an executable followed by 0 or more arguments")
		os.Exit(1)
	}

	executable := os.Args[1]
	args := os.Args[2:]

	reporter, err := syso.NewMTReporter(logger)
	if err != nil {
		logger.Fatalw("failed to create reporter", "err", err)
	}

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
