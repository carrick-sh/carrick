// Package cgosmoke is a tiny cgo conformance fixture for the go-conformance
// harness: it exercises the cgo paths that stress an emulator's runtime — a
// plain C call, C calling back into Go, and a C-created pthread calling back
// into Go (the needm/g0 stack-switch path). Built CGO_ENABLED=1 like the std
// test binaries; run identically under carrick and the Docker oracle.
package cgosmoke

/*
#include <pthread.h>
extern int goDouble(int x);            // Go, called from C
static int c_add(int a, int b) { return a + b; }
static int call_go(int x) { return goDouble(x); }
static void* tfn(void* a) { *(int*)a = goDouble(21); return 0; }
static int from_thread(void) {
    pthread_t t; int o = 0;
    pthread_create(&t, 0, tfn, &o);
    pthread_join(t, 0);
    return o;
}
*/
import "C"

//export goDouble
func goDouble(x C.int) C.int { return x * 2 }

// CAdd is a plain Go->C call.
func CAdd(a, b int) int { return int(C.c_add(C.int(a), C.int(b))) }

// Callback is C calling back into Go on the same thread.
func Callback(x int) int { return int(C.call_go(C.int(x))) }

// ThreadCallback is a C-created pthread calling back into Go.
func ThreadCallback() int { return int(C.from_thread()) }
