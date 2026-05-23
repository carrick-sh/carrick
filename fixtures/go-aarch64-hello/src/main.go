package main

import (
	"fmt"
	"sync"
)

func main() {
	// 1. Concurrency test via goroutines & channels (exercises clone & futex)
	var wg sync.WaitGroup
	ch := make(chan string, 3)

	wg.Add(3)
	for i := 1; i <= 3; i++ {
		go func(id int) {
			defer wg.Done()
			ch <- fmt.Sprintf("Worker %d completed", id)
		}(i)
	}

	wg.Wait()
	close(ch)

	// 2. Maps allocation & lookups (audits procfs /proc/self/maps at startup)
	m := make(map[string]int)
	m["first"] = 10
	m["second"] = 20

	// 3. Print deterministic hello output for assertions
	fmt.Println("hello from Go under carrick")
	for msg := range ch {
		fmt.Printf("Received: %s\n", msg)
	}
	fmt.Printf("Map lookup: first=%d, second=%d\n", m["first"], m["second"])
}
