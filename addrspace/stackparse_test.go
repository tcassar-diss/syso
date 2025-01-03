package addrspace_test

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tcassar-diss/syso/addrspace"
	"go.uber.org/zap"
)

func TestStackparseAssignPC(t *testing.T) {
	cases := []struct {
		name     string
		trace    [64]uint64
		expected string
	}{
		{
			name:     "only libc, one frame",
			trace:    [64]uint64{0x7ffff75b0000}, // stack traces come in 0-padded lengths of powers of two
			expected: "/usr/lib/x86_64-linux-gnu/libc.so.6",
		},
		{
			name:     "only libc, two frames",
			trace:    [64]uint64{0x7ffff75b0000, 0x7ffff75b0004},
			expected: "/usr/lib/x86_64-linux-gnu/libc.so.6",
		},
		{
			name:     "libssl via libc",
			trace:    [64]uint64{0x7ffff75b0000, 0x7ffff75b0004, 0x7ffff7e33000},
			expected: "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		},
		{
			name:     "anonymous, one frame",
			trace:    [64]uint64{0x7ffff7fbd000},
			expected: "anonymous",
		},
		{
			name:     "anonymous via libc",
			trace:    [64]uint64{0x7ffff75b0000, 0x7ffff7fbd000},
			expected: "anonymous",
		},
		{
			name:     "nginx via libc",
			trace:    [64]uint64{0x7ffff75b0000, 0x55555567c000},
			expected: "/usr/sbin/nginx",
		},
	}

	cwd, err := os.Getwd()
	require.NoError(t, err, "failed to get working directory")

	procmaps := addrspace.NewTestProcMaps(
		func(pid int32) string {
			return fmt.Sprintf(path.Join(cwd, "test_vas", "%d", "maps"), pid)
		},
	)

	stackparse := addrspace.NewStackParser(zap.NewNop().Sugar(), &procmaps)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lib, err := stackparse.AssignPC(2099258, c.trace, true)
			require.NoError(t, err)

			require.Equal(t, c.expected, lib)
		})
	}
}
