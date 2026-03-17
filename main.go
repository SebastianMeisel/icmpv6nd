package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const packetChannelSize = 2048

func main() {
	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	captureStats := &CaptureStats{}
	cache := NewNDCache(captureStats)
	cache.Start(ctx)

	registry := NewRegistry(cache)
	RegisterND(registry)

	packetCh := make(chan CapturedPacket, packetChannelSize)
	errCh := make(chan error, len(cfg.Interfaces))

	var wg sync.WaitGroup
	for _, iface := range cfg.Interfaces {
		iface := iface
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := RunCapture(ctx, iface, cfg.Capture.Filter, packetCh, captureStats); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("%s: %w", iface, err)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(packetCh)
		close(errCh)
	}()

	var seenInterrupt bool
	for packetCh != nil || errCh != nil {
		select {
		case <-ctx.Done():
			if !seenInterrupt {
				seenInterrupt = true
				log.Print("received Ctrl-C, shutting down gracefully...")
			}
		case captured, ok := <-packetCh:
			if !ok {
				packetCh = nil
				continue
			}
			registry.Process(captured)
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			log.Printf("capture error: %v", err)
		}
	}

	received, queued, dropped, errs := captureStats.Snapshot()
	log.Printf("all capture workers stopped (received=%d queued=%d dropped=%d errors=%d)", received, queued, dropped, errs)
}
