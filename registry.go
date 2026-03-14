package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Handler func(gopacket.Packet, *layers.ICMPv6)

type Registry struct {
	handlers map[uint8]Handler
}

func NewRegistry() *Registry {
	return &Registry{
		handlers: map[uint8]Handler{},
	}
}

func (r *Registry) Register(t uint8, h Handler) {
	r.handlers[t] = h
}

func (r *Registry) Process(packet gopacket.Packet) {

	layer := packet.Layer(layers.LayerTypeICMPv6)
	if layer == nil {
		return
	}

	icmp := layer.(*layers.ICMPv6)

	if h, ok := r.handlers[uint8(icmp.TypeCode.Type())]; ok {
		h(packet, icmp)
	}
}
