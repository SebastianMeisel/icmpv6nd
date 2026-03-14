package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketLayer interface {
	Name() string
	Summary() string
}

type EthernetInfo struct {
	Src string
	Dst string
}

func (e EthernetInfo) Name() string {
	return "Ethernet"
}

func (e EthernetInfo) Summary() string {
	return fmt.Sprintf("From src addr: %s to dst addr: %s", e.Src, e.Dst)
}

type IPv6Info struct {
	Src string
	Dst string
}

func (i IPv6Info) Name() string {
	return "IPv6"
}

func (i IPv6Info) Summary() string {
	return fmt.Sprintf("From src addr: %s to dst addr: %s", i.Src, i.Dst)
}

type TCPInfo struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
}

func (t TCPInfo) Name() string {
	return "TCP"
}

func (t TCPInfo) Summary() string {
	return fmt.Sprintf(
		"From src port: %d to dst port: %d, sequence number: %d",
		t.SrcPort, t.DstPort, t.Seq,
	)
}

func extractLayers(packet gopacket.Packet) []PacketLayer {
	var result []PacketLayer

	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Ethernet:
			result = append(result, EthernetInfo{
				Src: l.SrcMAC.String(),
				Dst: l.DstMAC.String(),
			})
		case *layers.IPv6:
			result = append(result, IPv6Info{
				Src: l.SrcIP.String(),
				Dst: l.DstIP.String(),
			})
		case *layers.TCP:
			result = append(result, TCPInfo{
				SrcPort: uint16(l.SrcPort),
				DstPort: uint16(l.DstPort),
				Seq:     l.Seq,
			})
		}
	}

	return result
}

func handlePacket(packet gopacket.Packet) {
	log.Println("_____________________________________________________________________")
	for _, layer := range extractLayers(packet) {
		log.Printf("[%s] %s\n", layer.Name(), layer.Summary())
	}
}

func main() {
	// Open the device for capturing
	handle, err := pcap.OpenLive("wlp170s0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter = "tcp and ip6"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}
