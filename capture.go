package main

import (
	"context"
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet = gopacket.Packet

type CapturedPacket struct {
	Interface string
	Packet    Packet
}

func RunCapture(ctx context.Context, iface string, filter string, out chan<- CapturedPacket) error {
	handle, err := pcap.OpenLive(iface, 65536, true, time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = ci

		select {
		case <-ctx.Done():
			return nil
		case out <- CapturedPacket{Interface: iface, Packet: packet}:
		}
	}
}
