package addrspace_test

import (
	"fmt"
	"os"
	"path"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tcassar-diss/syso/addrspace"
)

func TestReadAddrSpace(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err, "failed to get working directory")

	expected := []*addrspace.MemMap{
		{AddrStart: 0x7ffff7fbc000, AddrEnd: 0x7ffff7fbd000, PathName: "/dev/zero (deleted)"},
		{AddrStart: 0x7ffff7fc5000, AddrEnd: 0x7ffff7fff000, PathName: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},
		{AddrStart: 0x7ffff7d9d000, AddrEnd: 0x7ffff7daa000, PathName: "/usr/lib/x86_64-linux-gnu/libcap.so.2.66"},
		{AddrStart: 0x7ffff7800000, AddrEnd: 0x7ffff7d10000, PathName: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"},
		{AddrStart: 0x7ffff7f77000, AddrEnd: 0x7ffff7fa9000, PathName: "/usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0"},
		{AddrStart: 0x7ffff7400000, AddrEnd: 0x7ffff7605000, PathName: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		{AddrStart: 0x7ffff7717000, AddrEnd: 0x7ffff7800000, PathName: "/usr/lib/x86_64-linux-gnu/libm.so.6"},
		{AddrStart: 0x7ffff7daa000, AddrEnd: 0x7ffff7e06000, PathName: "/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2"},
		{AddrStart: 0x7ffff7edd000, AddrEnd: 0x7ffff7f77000, PathName: "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2"},
		{AddrStart: 0x7ffff7e33000, AddrEnd: 0x7ffff7edd000, PathName: "/usr/lib/x86_64-linux-gnu/libssl.so.3"},
		{AddrStart: 0x7ffff7e17000, AddrEnd: 0x7ffff7e33000, PathName: "/usr/lib/x86_64-linux-gnu/libz.so.1.3"},
		{AddrStart: 0x555555554000, AddrEnd: 0x555555696000, PathName: "/usr/sbin/nginx"},
		{AddrStart: 0x5555556b5000, AddrEnd: 0x555555740000, PathName: "[heap]"},
		{AddrStart: 0x7ffff7fbf000, AddrEnd: 0x7ffff7fc3000, PathName: "[vvar]"},
		{AddrStart: 0x7ffff7fc3000, AddrEnd: 0x7ffff7fc5000, PathName: "[vdso]"},
		{AddrStart: 0x7ffffffde000, AddrEnd: 0x7ffffffff000, PathName: "[stack]"},
		{AddrStart: 0xffffffffff600000, AddrEnd: 0xffffffffff601000, PathName: "[vsyscall]"},
	}

	procmaps := addrspace.NewTestProcMaps(
		func(pid int32) string {
			return fmt.Sprintf(path.Join(cwd, "test_vas", "%d", "maps"), pid)
		},
	)

	mmaps, err := procmaps.ReadAddrSpace(2099258, true)
	require.NoError(t, err, "failed to read address space")

	sf := func(a, b *addrspace.MemMap) int {
		if a.PathName < b.PathName {
			return -1
		}
		if a.PathName > b.PathName {
			return 1
		}
		return 0
	}

	slices.SortFunc(expected, sf)
	slices.SortFunc(mmaps, sf)

	require.Equal(t, expected, mmaps)

}

func TestAssignPC(t *testing.T) {
	cases := []struct {
		name     string
		pc       uint64
		expected string
	}{
		{
			name:     "lower bound address",
			pc:       0x7ffff75b0000,
			expected: "/usr/lib/x86_64-linux-gnu/libc.so.6",
		},
		{
			name:     "upper bound address",
			pc:       0x7ffff7e33000,
			expected: "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		},
		{
			name:     "anonymous",
			pc:       0x7ffff7fbd000,
			expected: "anonymous",
		},
	}

	cwd, err := os.Getwd()
	require.NoError(t, err, "failed to get working directory")

	procmaps := addrspace.NewTestProcMaps(
		func(pid int32) string {
			return fmt.Sprintf(path.Join(cwd, "test_vas", "%d", "maps"), pid)
		},
	)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lib, err := procmaps.AssignPC(c.pc, 2099258, true)
			require.NoError(t, err)

			require.Equal(t, c.expected, lib)
		})
	}
}
