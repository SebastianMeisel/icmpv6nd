package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func RegisterND(r *Registry) {
	r.Register(layers.ICMPv6TypeNeighborSolicitation, handleNS)
	r.Register(layers.ICMPv6TypeNeighborAdvertisement, handleNA)
	r.Register(layers.ICMPv6TypeRouterAdvertisement, handleRA)
}

func handleNS(packet gopacket.Packet, icmp *layers.ICMPv6, iface string) *NDRecord {
	l := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if l == nil {
		return nil
	}

	ns := l.(*layers.ICMPv6NeighborSolicitation)
	src := packetIPv6Source(packet)
	meta := map[string]string{
		"target": ns.TargetAddress.String(),
	}

	for _, opt := range ns.Options {
		if opt.Type == layers.ICMPv6OptSourceAddress {
			meta["source-mac"] = formatMAC(opt.Data)
		}
	}

	return newNDRecord(iface, "Neighbor Solicitation", src, ns.TargetAddress.String(), meta)
}

func handleNA(packet gopacket.Packet, icmp *layers.ICMPv6, iface string) *NDRecord {
	l := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if l == nil {
		return nil
	}

	na := l.(*layers.ICMPv6NeighborAdvertisement)
	src := packetIPv6Source(packet)
	meta := map[string]string{
		"target": na.TargetAddress.String(),
		"flags":  describeNAFlags(na),
	}

	for _, opt := range na.Options {
		if opt.Type == layers.ICMPv6OptTargetAddress {
			meta["target-mac"] = formatMAC(opt.Data)
		}
	}

	return newNDRecord(iface, "Neighbor Advertisement", src, na.TargetAddress.String(), meta)
}

func handleRA(packet gopacket.Packet, icmp *layers.ICMPv6, iface string) *NDRecord {
	l := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if l == nil {
		return nil
	}

	ra := l.(*layers.ICMPv6RouterAdvertisement)
	src := packetIPv6Source(packet)
	meta := map[string]string{
		"hop-limit": fmt.Sprintf("%d", ra.HopLimit),
		"lifetime":  fmt.Sprintf("%ds", ra.RouterLifetime),
		"reachable": fmt.Sprintf("%dms", ra.ReachableTime),
		"retrans":   fmt.Sprintf("%dms", ra.RetransTimer),
		"flags":     describeRAFlags(ra),
	}

	if opts := describeRAOptions(ra.Options); opts != "none" {
		meta["options"] = opts
	}

	return newNDRecord(iface, "Router Advertisement", src, "ff02::1", meta)
}

func packetIPv6Source(packet gopacket.Packet) string {
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		return ipLayer.(*layers.IPv6).SrcIP.String()
	}
	return "unknown"
}

func describeNAFlags(na *layers.ICMPv6NeighborAdvertisement) string {
	var parts []string
	if na.Router() {
		parts = append(parts, "router")
	}
	if na.Solicited() {
		parts = append(parts, "solicited")
	}
	if na.Override() {
		parts = append(parts, "override")
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	return strings.Join(parts, ", ")
}

func describeRAFlags(ra *layers.ICMPv6RouterAdvertisement) string {
	var parts []string

	if ra.ManagedAddressConfig() {
		parts = append(parts, "managed-addresses(DHCPv6)")
	}
	if ra.OtherConfig() {
		parts = append(parts, "other-config(DHCPv6)")
	}
	if ra.Flags&0x20 != 0 {
		parts = append(parts, "home-agent")
	}

	switch (ra.Flags >> 3) & 0x3 {
	case 0x1:
		parts = append(parts, "router-pref=high")
	case 0x0:
		parts = append(parts, "router-pref=medium")
	case 0x3:
		parts = append(parts, "router-pref=low")
	default:
		parts = append(parts, "router-pref=reserved")
	}

	if len(parts) == 0 {
		parts = append(parts, "none")
	}

	return fmt.Sprintf("%s [raw=%08b]", strings.Join(parts, ", "), ra.Flags)
}

func describeRAOptions(opts []layers.ICMPv6Option) string {
	if len(opts) == 0 {
		return "none"
	}

	parts := make([]string, 0, len(opts))
	for _, opt := range opts {
		parts = append(parts, describeRAOption(opt))
	}
	return strings.Join(parts, " |\n        ")
}

func describeRAOption(opt layers.ICMPv6Option) string {
	switch opt.Type {
	case layers.ICMPv6OptSourceAddress:
		return fmt.Sprintf("%s mac=%s", opt.Type, formatMAC(opt.Data))

	case layers.ICMPv6OptTargetAddress:
		return fmt.Sprintf("%s mac=%s", opt.Type, formatMAC(opt.Data))

	case layers.ICMPv6OptMTU:
		if len(opt.Data) < 6 {
			return fmt.Sprintf("%s invalid(len=%d)", opt.Type, len(opt.Data))
		}
		mtu := binary.BigEndian.Uint32(opt.Data[2:6])
		return fmt.Sprintf("%s mtu=%d", opt.Type, mtu)

	case layers.ICMPv6OptPrefixInfo:
		return describePrefixInfo(opt)

	default:
		return fmt.Sprintf("%s len=%d data=%x", opt.Type, len(opt.Data), opt.Data)
	}
}

func describePrefixInfo(opt layers.ICMPv6Option) string {
	if len(opt.Data) < 30 {
		return fmt.Sprintf("%s invalid(len=%d)", opt.Type, len(opt.Data))
	}

	prefixLen := opt.Data[0]
	flags := opt.Data[1]
	validLifetime := binary.BigEndian.Uint32(opt.Data[2:6])
	preferredLifetime := binary.BigEndian.Uint32(opt.Data[6:10])
	prefix := net.IP(opt.Data[14:30])

	var flagParts []string
	if flags&0x80 != 0 {
		flagParts = append(flagParts, "on-link")
	}
	if flags&0x40 != 0 {
		flagParts = append(flagParts, "autonomous")
	}
	if len(flagParts) == 0 {
		flagParts = append(flagParts, "none")
	}

	return fmt.Sprintf(
		"%s prefix=%s/%d flags=%s valid=%ds preferred=%ds",
		opt.Type,
		prefix,
		prefixLen,
		strings.Join(flagParts, ","),
		validLifetime,
		preferredLifetime,
	)
}

func formatMAC(data []byte) string {
	if len(data) == 0 {
		return "unknown"
	}
	return net.HardwareAddr(data).String()
}

func newNDRecord(iface string, kind string, source string, subject string, meta map[string]string) *NDRecord {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, meta[k]))
	}

	return &NDRecord{
		Key:       fmt.Sprintf("%s|%s|%s|%s|%s", iface, kind, source, subject, strings.Join(parts, "|")),
		Interface: iface,
		Kind:      kind,
		Source:    source,
		Subject:   subject,
		Details:   parts,
	}
}
