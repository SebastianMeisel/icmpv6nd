package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Handler func(gopacket.Packet, *layers.ICMPv6) *NDRecord

type Registry struct {
	handlers map[uint8]Handler
	cache    *NDCache
}

func NewRegistry(cache *NDCache) *Registry {
	return &Registry{
		handlers: map[uint8]Handler{},
		cache:    cache,
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
		if record := h(packet, icmp); record != nil {
			r.cache.Add(*record)
		}
	}
}
