package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type (
	Packet = gopacket.Packet

	CapturedPacket struct {
		Interface string
		Packet    Packet
	}

	CaptureStats struct {
		received uint64
		queued   uint64
		dropped  uint64
		errors   uint64
	}
)

func (s *CaptureStats) IncReceived() {
	atomic.AddUint64(&s.received, 1)
}

func (s *CaptureStats) IncQueued() {
	atomic.AddUint64(&s.queued, 1)
}

func (s *CaptureStats) IncDropped() {
	atomic.AddUint64(&s.dropped, 1)
}

func (s *CaptureStats) IncErrors() {
	atomic.AddUint64(&s.errors, 1)
}

func (s *CaptureStats) Snapshot() (received, queued, dropped, errs uint64) {
	return atomic.LoadUint64(&s.received), atomic.LoadUint64(&s.queued), atomic.LoadUint64(&s.dropped), atomic.LoadUint64(&s.errors)
}

func RunCapture(ctx context.Context, iface string, filter string, out chan<- CapturedPacket, stats *CaptureStats) error {
	handle, err := pcap.OpenLive(iface, 65536, true, time.Second)
	if err != nil {
		if stats != nil {
			stats.IncErrors()
		}
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		if stats != nil {
			stats.IncErrors()
		}
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
			if stats != nil {
				stats.IncErrors()
			}
			return err
		}

		if stats != nil {
			stats.IncReceived()
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = ci

		captured := CapturedPacket{Interface: iface, Packet: packet}
		select {
		case <-ctx.Done():
			return nil
		case out <- captured:
			if stats != nil {
				stats.IncQueued()
			}
		default:
			if stats != nil {
				stats.IncDropped()
			}
		}
	}
}
