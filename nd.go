package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func RegisterND(r *Registry) {
	r.Register(layers.ICMPv6TypeNeighborSolicitation, handleNS)
	r.Register(layers.ICMPv6TypeNeighborAdvertisement, handleNA)
	r.Register(layers.ICMPv6TypeRouterAdvertisement, handleRA)
}

func handleNS(packet gopacket.Packet, icmp *layers.ICMPv6) {

	l := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if l == nil {
		return
	}

	ns := l.(*layers.ICMPv6NeighborSolicitation)

	fmt.Printf("Neighbor Solicitation target=%s\n", ns.TargetAddress)
}

func handleNA(packet gopacket.Packet, icmp *layers.ICMPv6) {

	l := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if l == nil {
		return
	}

	na := l.(*layers.ICMPv6NeighborAdvertisement)

	fmt.Printf("Neighbor Advertisement target=%s\n", na.TargetAddress)
}

func handleRA(packet gopacket.Packet, icmp *layers.ICMPv6) {

	l := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if l == nil {
		return
	}

	ra := l.(*layers.ICMPv6RouterAdvertisement)

	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		fmt.Printf("Router %s advertises network\n", ip.SrcIP)
	}
	fmt.Printf(
		"Router Advertisement hopLimit=%d lifetime=%d flags=%08b\n",
		ra.HopLimit,
		ra.RouterLifetime,
		ra.Flags,
	)
	fmt.Printf(
		"                     options: %d\n",
		ra.Options,
	)
}
