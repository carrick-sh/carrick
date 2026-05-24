package main

import (
	"arena"
	"fmt"
	"os"
	"unsafe"
)

const userArenaChunkBytes = 8 << 20

type largeScalar [userArenaChunkBytes + 1]byte

func main() {
	value := new(largeScalar)
	for i := range value {
		value[i] = 123
	}

	a := arena.NewArena()
	defer a.Free()

	got := arena.New[largeScalar](a)
	*got = *value

	for i := range got {
		if got[i] != value[i] {
			fmt.Printf("mismatch index=%d got=%d want=%d size=%d dst=%#x src=%#x\n",
				i, got[i], value[i], unsafe.Sizeof(*got), uintptr(unsafe.Pointer(got)), uintptr(unsafe.Pointer(value)))
			os.Exit(1)
		}
	}

	fmt.Printf("ok size=%d dst=%#x src=%#x\n", unsafe.Sizeof(*got), uintptr(unsafe.Pointer(got)), uintptr(unsafe.Pointer(value)))
}
