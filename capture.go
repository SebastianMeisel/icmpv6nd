package main

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Packet = gopacket.Packet

type CapturedPacket struct {
	Interface string
	Packet    Packet
}

func RunCapture(ctx context.Context, iface string, filter string, out chan<- CapturedPacket) error {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set filter on %s: %w", iface, err)
	}

	go func() {
		<-ctx.Done()
		handle.Close()
	}()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet, ok := <-packets:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("packet source for %s stopped", iface)
			}
			out <- CapturedPacket{Interface: iface, Packet: packet}
		}
	}
}
