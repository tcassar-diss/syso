package addrspace

import "go.uber.org/zap"

// StackParser will use stack traces to identify the library responsible for calling libc syscall wrapper.
type StackParser struct {
	logger *zap.SugaredLogger
}
