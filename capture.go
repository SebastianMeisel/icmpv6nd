package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Packet = gopacket.Packet

func RunCapture(iface string, filter string, handler func(Packet)) error {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		return err
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		handler(packet)
	}
	return nil
}
