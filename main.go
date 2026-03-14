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

type LayerFactory func(gopacket.Layer) (PacketLayer, bool)

type LayerRegistry struct {
	factories map[gopacket.LayerType]LayerFactory
}

func NewLayerRegistry() *LayerRegistry {
	return &LayerRegistry{
		factories: make(map[gopacket.LayerType]LayerFactory),
	}
}

func (r *LayerRegistry) Register(layerType gopacket.LayerType, factory LayerFactory) {
	r.factories[layerType] = factory
}

func (r *LayerRegistry) Build(layer gopacket.Layer) (PacketLayer, bool) {
	factory, ok := r.factories[layer.LayerType()]
	if !ok {
		return nil, false
	}
	return factory(layer)
}

func (r *LayerRegistry) Extract(packet gopacket.Packet) []PacketLayer {
	result := make([]PacketLayer, 0, len(packet.Layers()))
	for _, layer := range packet.Layers() {
		if packetLayer, ok := r.Build(layer); ok {
			result = append(result, packetLayer)
		}
	}
	return result
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

func defaultLayerRegistry() *LayerRegistry {
	registry := NewLayerRegistry()

	registry.Register(layers.LayerTypeEthernet, func(layer gopacket.Layer) (PacketLayer, bool) {
		ethernet, ok := layer.(*layers.Ethernet)
		if !ok {
			return nil, false
		}
		return EthernetInfo{
			Src: ethernet.SrcMAC.String(),
			Dst: ethernet.DstMAC.String(),
		}, true
	})

	registry.Register(layers.LayerTypeIPv6, func(layer gopacket.Layer) (PacketLayer, bool) {
		ip6, ok := layer.(*layers.IPv6)
		if !ok {
			return nil, false
		}
		return IPv6Info{
			Src: ip6.SrcIP.String(),
			Dst: ip6.DstIP.String(),
		}, true
	})

	registry.Register(layers.LayerTypeTCP, func(layer gopacket.Layer) (PacketLayer, bool) {
		tcp, ok := layer.(*layers.TCP)
		if !ok {
			return nil, false
		}
		return TCPInfo{
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Seq:     tcp.Seq,
		}, true
	})

	return registry
}

func handlePacket(packet gopacket.Packet, registry *LayerRegistry) {
	for _, layer := range registry.Extract(packet) {
		log.Printf("[%s] %s", layer.Name(), layer.Summary())
	}
}

func main() {
	registry := defaultLayerRegistry()

	// Open the device for capturing
	handle, err := pcap.OpenLive("wlp170s0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "tcp and ip6"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet, registry)
	}
}
