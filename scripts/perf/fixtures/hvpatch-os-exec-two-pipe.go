// hvpatch-os-exec-two-pipe is a bounded reproducer for the Phase 4 shared-VM
// fork/exec pipe-lifetime failure. Each child gets independent stdout and
// stderr pipes, matching os/exec's writerDescriptor path. The watchdog reports
// the exact worker iteration and parent pipe fd pair before dumping goroutines.
//
// Run inside the canonical carrick Go image; this source is not a host test.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	workers          = 4
	childrenPerRound = 10
	rounds           = 100
)

func exportedValue(value reflect.Value) reflect.Value {
	return reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem()
}

func parentPipeFDs(command *exec.Cmd) uint64 {
	pipes := reflect.ValueOf(command).Elem().FieldByName("parentIOPipes")
	var packed uint64
	for index := 0; index < pipes.Len() && index < 2; index++ {
		closer := exportedValue(pipes.Index(index)).Interface().(io.Closer)
		file, ok := closer.(*os.File)
		if !ok {
			continue
		}
		packed |= uint64(file.Fd()) << (32 * index)
	}
	return packed
}

func main() {
	for round := 1; round <= rounds; round++ {
		var group sync.WaitGroup
		var iteration [workers]atomic.Int32
		var pipes [workers]atomic.Uint64
		for worker := 0; worker < workers; worker++ {
			group.Add(1)
			go func(worker int) {
				defer group.Done()
				iteration[worker].Store(-1)
				for child := 0; child < childrenPerRound; child++ {
					var stdout, stderr bytes.Buffer
					command := exec.Command("/bin/true")
					command.Stdout = &stdout
					command.Stderr = &stderr
					if err := command.Start(); err != nil {
						panic(err)
					}
					iteration[worker].Store(int32(child))
					pipes[worker].Store(parentPipeFDs(command))
					if err := command.Wait(); err != nil {
						panic(err)
					}
				}
				iteration[worker].Store(-10)
			}(worker)
		}

		done := make(chan struct{})
		go func() {
			group.Wait()
			close(done)
		}()
		select {
		case <-done:
			fmt.Printf("ROUND_OK_%d\n", round)
		case <-time.After(5 * time.Second):
			fmt.Fprintf(os.Stderr, "ROUND_TIMEOUT_%d status=[", round)
			for worker := 0; worker < workers; worker++ {
				if worker != 0 {
					fmt.Fprint(os.Stderr, " ")
				}
				fmt.Fprint(os.Stderr, iteration[worker].Load())
			}
			fmt.Fprint(os.Stderr, "] pipes=[")
			for worker := 0; worker < workers; worker++ {
				if worker != 0 {
					fmt.Fprint(os.Stderr, " ")
				}
				fmt.Fprintf(os.Stderr, "%x", pipes[worker].Load())
			}
			fmt.Fprintln(os.Stderr, "]")
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
			if os.Getenv("HVPATCH_REDUCER_PAUSE") != "" {
				fmt.Fprintln(os.Stderr, "WATCHDOG_PAUSED_300S")
				time.Sleep(300 * time.Second)
			}
			os.Exit(124)
		}
	}
	fmt.Println("HARNESS_DONE")
}
