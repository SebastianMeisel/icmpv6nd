package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	cache := NewNDCache()
	registry := NewRegistry(cache)
	RegisterND(registry)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	packets := make(chan CapturedPacket)
	errCh := make(chan error, len(cfg.Interfaces))

	var wg sync.WaitGroup
	for _, iface := range cfg.Interfaces {
		iface := iface
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := RunCapture(ctx, iface, cfg.Capture.Filter, packets); err != nil {
				errCh <- err
				stop()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(packets)
		close(errCh)
	}()

	for packet := range packets {
		registry.Process(packet)
	}

	for err := range errCh {
		if err != nil {
			log.Printf("capture stopped: %v", err)
		}
	}
}
