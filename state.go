package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type (
	NDRecord struct {
		Key       string
		Interface string
		Kind      string
		Source    string
		Subject   string
		Details   []string
		Count     int
	}

	NDCache struct {
		mu             sync.Mutex
		entries        map[string]*NDRecord
		order          []string
		total          int
		dropped        int
		dirty          bool
		maxEntries     int
		renderInterval time.Duration
		maxLineLen     int
		maxDetails     int
		notifyCh       chan struct{}
	}

	ndSnapshot struct {
		Total   int
		Dropped int
		Entries []*NDRecord
	}
)

const (
	defaultCacheMaxEntries     = 1024
	defaultCacheRenderInterval = 250 * time.Millisecond
	defaultCacheMaxLineLen     = 160
	defaultCacheMaxDetails     = 12
)

func NewNDCache() *NDCache {
	return &NDCache{
		entries:        map[string]*NDRecord{},
		maxEntries:     defaultCacheMaxEntries,
		renderInterval: defaultCacheRenderInterval,
		maxLineLen:     defaultCacheMaxLineLen,
		maxDetails:     defaultCacheMaxDetails,
		dirty:          true,
		notifyCh:       make(chan struct{}, 1),
	}
}

func (c *NDCache) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(c.renderInterval)
		defer ticker.Stop()

		c.renderSnapshot(c.snapshot())

		for {
			select {
			case <-ctx.Done():
				if c.consumeDirty() {
					c.renderSnapshot(c.snapshot())
				}
				return
			case <-c.notifyCh:
				if !c.consumeDirty() {
					continue
				}
				c.renderSnapshot(c.snapshot())
			case <-ticker.C:
				if !c.consumeDirty() {
					continue
				}
				c.renderSnapshot(c.snapshot())
			}
		}
	}()
}

func (c *NDCache) Add(record NDRecord) {
	record = c.normalizeRecord(record)

	c.mu.Lock()
	c.total++
	if existing, ok := c.entries[record.Key]; ok {
		existing.Count++
		c.dirty = true
		c.mu.Unlock()
		c.notifyRender()
		return
	}

	if len(c.entries) >= c.maxEntries {
		oldestKey := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldestKey)
		c.dropped++
	}

	record.Count = 1
	copyRecord := record
	c.entries[record.Key] = &copyRecord
	c.order = append(c.order, record.Key)
	c.dirty = true
	c.mu.Unlock()

	c.notifyRender()
}

func (c *NDCache) notifyRender() {
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}
}

func (c *NDCache) consumeDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.dirty {
		return false
	}
	c.dirty = false
	return true
}

func (c *NDCache) snapshot() ndSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := ndSnapshot{
		Total:   c.total,
		Dropped: c.dropped,
		Entries: make([]*NDRecord, 0, len(c.order)),
	}

	for _, key := range c.order {
		entry, ok := c.entries[key]
		if !ok {
			continue
		}
		copyEntry := *entry
		copyEntry.Details = append([]string(nil), entry.Details...)
		s.Entries = append(s.Entries, &copyEntry)
	}

	return s
}

func (c *NDCache) renderSnapshot(s ndSnapshot) {
	var b strings.Builder
	b.Grow(1024 + len(s.Entries)*128)

	b.WriteString("\033[H\033[2J")
	b.WriteString("IPv6 Neighbor Discovery cache\n")
	fmt.Fprintf(&b, "captured packets: %d\n", s.Total)
	fmt.Fprintf(&b, "cached entries   : %d/%d\n", len(s.Entries), c.maxEntries)
	fmt.Fprintf(&b, "evicted entries  : %d\n\n", s.Dropped)

	if len(s.Entries) == 0 {
		b.WriteString("waiting for packets...\n")
		_, _ = fmt.Fprint(os.Stdout, b.String())
		return
	}

	sort.SliceStable(s.Entries, func(i, j int) bool {
		if s.Entries[i].Interface != s.Entries[j].Interface {
			return s.Entries[i].Interface < s.Entries[j].Interface
		}
		if s.Entries[i].Kind != s.Entries[j].Kind {
			return s.Entries[i].Kind < s.Entries[j].Kind
		}
		if s.Entries[i].Source != s.Entries[j].Source {
			return s.Entries[i].Source < s.Entries[j].Source
		}
		return s.Entries[i].Subject < s.Entries[j].Subject
	})

	for _, entry := range s.Entries {
		fmt.Fprintf(&b, "[%3d] %s @ %s\n", entry.Count, entry.Kind, entry.Interface)
		fmt.Fprintf(&b, "      source : %s\n", entry.Source)
		fmt.Fprintf(&b, "      subject: %s\n", entry.Subject)

		for _, detail := range entry.Details {
			fmt.Fprintf(&b, "      - %s\n", detail)
		}
		b.WriteByte('\n')
	}
	_, _ = fmt.Fprint(os.Stdout, b.String())
}

func (c *NDCache) normalizeRecord(record NDRecord) NDRecord {
	record.Interface = sanitizeTerminalLine(record.Interface, c.maxLineLen)
	record.Kind = sanitizeTerminalLine(record.Kind, c.maxLineLen)
	record.Source = sanitizeTerminalLine(record.Source, c.maxLineLen)
	record.Subject = sanitizeTerminalLine(record.Subject, c.maxLineLen)

	if len(record.Details) > c.maxDetails {
		record.Details = append([]string(nil), record.Details[:c.maxDetails]...)
		record.Details = append(record.Details, fmt.Sprintf("... %d more detail(s)", len(record.Details)-c.maxDetails))
	}

	for i := range record.Details {
		record.Details[i] = sanitizeTerminalLine(record.Details[i], c.maxLineLen)
	}

	record.Key = sanitizeTerminalLine(record.Key, c.maxLineLen*2)
	return record
}

func sanitizeTerminalLine(s string, maxLen int) string {
	if s == "" {
		return "-"
	}

	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)

	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if s == "" {
		return "-"
	}

	runes := []rune(s)
	if len(runes) > maxLen {
		return string(runes[:maxLen-1]) + "…"
	}
	return s
}
