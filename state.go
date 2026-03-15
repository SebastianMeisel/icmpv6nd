package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/inancgumus/screen"
)

type NDRecord struct {
	Key       string
	Interface string
	Kind      string
	Source    string
	Subject   string
	Details   []string
	Count     int
}

type NDCache struct {
	mu      sync.Mutex
	entries map[string]*NDRecord
	order   []string
	total   int
}

func NewNDCache() *NDCache {
	return &NDCache{
		entries: map[string]*NDRecord{},
	}
}

func (c *NDCache) Add(record NDRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.total++

	if existing, ok := c.entries[record.Key]; ok {
		existing.Count++
		c.renderLocked()
		return
	}

	record.Count = 1
	copyRecord := record
	c.entries[record.Key] = &copyRecord
	c.order = append(c.order, record.Key)
	c.renderLocked()
}

func (c *NDCache) renderLocked() {
	var b strings.Builder
	screen.Clear()
	b.WriteString("\033[H\033[2J")
	b.WriteString("IPv6 Neighbor Discovery cache\n")
	b.WriteString(fmt.Sprintf("captured packets: %d\n\n", c.total))

	if len(c.order) == 0 {
		b.WriteString("waiting for packets...\n")
		_, _ = fmt.Fprint(os.Stdout, b.String())
		return
	}

	entries := make([]*NDRecord, 0, len(c.entries))
	for _, key := range c.order {
		entries = append(entries, c.entries[key])
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Interface != entries[j].Interface {
			return entries[i].Interface < entries[j].Interface
		}
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Subject < entries[j].Subject
	})

	for _, entry := range entries {
		b.WriteString(fmt.Sprintf("[%3d] %s\n", entry.Count, entry.Kind))
		b.WriteString(fmt.Sprintf("      iface  : %s\n", entry.Interface))
		b.WriteString(fmt.Sprintf("      source : %s\n", entry.Source))
		b.WriteString(fmt.Sprintf("      subject: %s\n", entry.Subject))
		for _, detail := range entry.Details {
			b.WriteString(fmt.Sprintf("      - %s\n", detail))
		}
		b.WriteByte('\n')
	}

	_, _ = fmt.Fprint(os.Stdout, b.String())
}
