package main

import (
	"fmt"
	"os"

	"github.com/tcassar-diss/syso"
	"go.uber.org/zap"
)

func main() {
	prodLog, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	logger := prodLog.Sugar()

	pm := syso.NewProcMaps(logger)
	defer pm.Close()

	pid := os.Getpid()

	logger.Infow("Getting address space", "pid", pid)

	mmap, err := pm.ByPID(int32(pid), true)
	if err != nil {
		logger.Fatalw("failed to parse proc maps", "pid", pid, "err", err)
	}

	for _, m := range mmap {
		fmt.Printf("AddrStart: %d\tAddrEnd: %d\tPath: %s\n", m.AddrStart, m.AddrEnd, m.PathName)
	}

	logger.Info("From cache")

	mmap, err = pm.ByPID(int32(pid), false)
	if err != nil {
		logger.Fatalw("failed to parse proc maps", "pid", pid, "err", err)
	}

	for _, m := range mmap {
		fmt.Printf("AddrStart: %d\tAddrEnd: %d\tPath: %s\n", m.AddrStart, m.AddrEnd, m.PathName)
	}

	logger.Info("dirty=true")

	mmap, err = pm.ByPID(int32(pid), true)
	if err != nil {
		logger.Fatalw("failed to parse proc maps", "pid", pid, "err", err)
	}

	for _, m := range mmap {
		fmt.Printf("AddrStart: %d\tAddrEnd: %d\tPath: %s\n", m.AddrStart, m.AddrEnd, m.PathName)
	}
}
