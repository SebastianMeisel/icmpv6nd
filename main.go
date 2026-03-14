package main

import "log"

func main() {

	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	registry := NewRegistry()
	RegisterND(registry)

	err = RunCapture(cfg.Interface, cfg.Capture.Filter, func(p Packet) {
		registry.Process(p)
	})

	if err != nil {
		log.Fatal(err)
	}
}
