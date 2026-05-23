package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type DemoResponse struct {
	Status      string `json:"status"`
	Runtime     string `json:"runtime"`
	Concurrency string `json:"concurrency"`
}

func main() {
	// Parse benchmark flags
	benchmarkFlag := flag.Bool("benchmark", false, "Run in benchmark mode")
	concurrencyFlag := flag.Int("c", 10, "Concurrency level for benchmark")
	requestsFlag := flag.Int("n", 1000, "Total number of requests for benchmark")
	flag.Parse()

	// 1. Allocate a free TCP port dynamically on loopback
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// 2. Set up the concurrent HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := DemoResponse{
			Status:      "success",
			Runtime:     "carrick",
			Concurrency: "enabled",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Handler: mux,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Run the server in a background goroutine (exercises clone, futex, epoll-netpoller)
	go func() {
		defer wg.Done()
		if err := server.Serve(listener); err != http.ErrServerClosed {
			panic(err)
		}
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d/demo", port)

	if *benchmarkFlag {
		if *concurrencyFlag <= 0 {
			fmt.Fprintln(os.Stderr, "benchmark concurrency must be positive")
			os.Exit(2)
		}
		if *requestsFlag < 0 {
			fmt.Fprintln(os.Stderr, "benchmark requests must be non-negative")
			os.Exit(2)
		}
		fmt.Printf("Running network benchmark: concurrency=%d, total_requests=%d\n", *concurrencyFlag, *requestsFlag)

		start := time.Now()

		var clientWg sync.WaitGroup
		baseRequests := *requestsFlag / *concurrencyFlag
		extraRequests := *requestsFlag % *concurrencyFlag

		for i := 0; i < *concurrencyFlag; i++ {
			requestsForWorker := baseRequests
			if i < extraRequests {
				requestsForWorker++
			}
			clientWg.Add(1)
			go func(requestCount int) {
				defer clientWg.Done()
				// Using a custom client per worker to parallelize TCP connections
				client := &http.Client{
					Timeout: 5 * time.Second,
					Transport: &http.Transport{
						MaxIdleConnsPerHost: *concurrencyFlag,
					},
				}
				for j := 0; j < requestCount; j++ {
					req, err := http.NewRequest("GET", url, nil)
					if err != nil {
						panic(err)
					}
					res, err := client.Do(req)
					if err != nil {
						panic(err)
					}
					_, _ = io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}(requestsForWorker)
		}
		clientWg.Wait()

		elapsed := time.Since(start)
		reqsPerSec := 0.0
		if *requestsFlag > 0 {
			reqsPerSec = float64(*requestsFlag) / elapsed.Seconds()
		}
		fmt.Printf("Benchmark completed: elapsed=%s, rate=%.2f req/sec\n", elapsed, reqsPerSec)
	} else {
		// 3. Launch the Client to fetch the JSON payload
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			panic(err)
		}

		res, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}

		var parsed DemoResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			panic(err)
		}

		// 4. Print deterministic, assertion-friendly output
		fmt.Printf("Client received status: %s\n", parsed.Status)
		fmt.Printf("Client received runtime: %s\n", parsed.Runtime)
		fmt.Printf("Client received concurrency: %s\n", parsed.Concurrency)
	}

	// 5. Gracefully shut down the server to complete the process cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}

	wg.Wait()
	if !*benchmarkFlag {
		fmt.Println("Graceful shutdown completed successfully")
	}
}
