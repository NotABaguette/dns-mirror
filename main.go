// server.go
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// Config holds server configuration
type Config struct {
	Listen struct {
		UDP string `yaml:"udp"`
		TCP string `yaml:"tcp"`
	} `yaml:"listen"`
	CSV             string   `yaml:"csv"`
	Upstreams       []string `yaml:"upstreams"`
	Fallbacks       []string `yaml:"fallbacks"`
	ClientTimeoutMs int      `yaml:"client_timeout_ms"`
	Cache           struct {
		Enabled     bool `yaml:"enabled"`
		MaxEntries  int  `yaml:"max_entries"`
		DefaultTTL  int  `yaml:"default_ttl"`
	} `yaml:"cache"`
}

// Cache entry
type cacheEntry struct {
	msg    *dns.Msg
	expire time.Time
}

// DNSHandler is the main server structure
type DNSHandler struct {
	staticLock sync.RWMutex
	static     map[string][]dns.RR // keyed by lower-case FQDN with trailing dot

	cfg Config

	client *dns.Client

	upstreams []string
	fallbacks []string

	cacheLock sync.RWMutex
	cache     map[string]cacheEntry // key: qname|qtype|qclass
	cMax      int
}

// normalizeName returns lowercased FQDN with trailing dot
func normalizeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		s = s + "."
	}
	return strings.ToLower(s)
}

// cacheKey constructs a cache key for a question
func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%s|%d|%d", normalizeName(q.Name), q.Qtype, q.Qclass)
}

// loadCSV loads static RRs from CSV into handler.static
func (h *DNSHandler) loadCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	records, err := r.ReadAll()
	if err != nil {
		return err
	}

	tmp := make(map[string][]dns.RR)
	for _, rec := range records {
		// Skip empty or comment lines
		if len(rec) == 0 || strings.HasPrefix(strings.TrimSpace(rec[0]), "#") {
			continue
		}
		// allow header detection: if first column is "name" skip header
		if strings.ToLower(strings.TrimSpace(rec[0])) == "name" {
			continue
		}
		if len(rec) < 4 {
			// try allowing 3 columns: name,type,value with default ttl
			if len(rec) < 3 {
				continue
			}
		}
		name := normalizeName(rec[0])
		typ := strings.ToUpper(strings.TrimSpace(rec[1]))
		ttl := uint32(300)
		if len(rec) >= 3 {
			// if ttl numeric provided in 3rd column assumed; otherwise 3rd is value
		}
		var val string
		// support both: name,type,ttl,value  and name,type,value (ttl optional)
		if len(rec) >= 4 {
			// name,type,ttl,value
			if t, err := strconv.Atoi(strings.TrimSpace(rec[2])); err == nil {
				ttl = uint32(t)
			}
			val = rec[3]
		} else if len(rec) == 3 {
			// name,type,value
			val = rec[2]
		}
		val = strings.TrimSpace(val)
		// Build RR string in zonefile-like presentation
		rrStr := fmt.Sprintf("%s %d IN %s %s", name, ttl, typ, val)
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed parsing rr from CSV: %q -> %v\n", rrStr, err)
			continue
		}
		tmp[name] = append(tmp[name], rr)
	}

	h.staticLock.Lock()
	h.static = tmp
	h.staticLock.Unlock()
	return nil
}

func (h *DNSHandler) loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	h.cfg = cfg
	if cfg.ClientTimeoutMs <= 0 {
		cfg.ClientTimeoutMs = 2000
	}
	h.client = &dns.Client{
		Net:     "udp",
		Timeout: time.Duration(cfg.ClientTimeoutMs) * time.Millisecond,
	}
	h.upstreams = append([]string{}, cfg.Upstreams...)
	h.fallbacks = append([]string{}, cfg.Fallbacks...)
	if cfg.Cache.MaxEntries <= 0 {
		cfg.Cache.MaxEntries = 100000
	}
	h.cMax = cfg.Cache.MaxEntries
	return nil
}

// lookupStatic returns RRs from CSV (if any) for the qname and qtype
func (h *DNSHandler) lookupStatic(qname string, qtype uint16) []dns.RR {
	name := normalizeName(qname)
	h.staticLock.RLock()
	rrs := h.static[name]
	h.staticLock.RUnlock()
	if rrs == nil {
		return nil
	}
	// filter by type (if type==ANY, return all)
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

// tryCache tries to return cached response (deep copy) if valid
func (h *DNSHandler) tryCache(q dns.Question) *dns.Msg {
	if !h.cfg.Cache.Enabled {
		return nil
	}
	key := cacheKey(q)
	h.cacheLock.RLock()
	e, ok := h.cache[key]
	h.cacheLock.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(e.expire) {
		// expired: delete
		h.cacheLock.Lock()
		delete(h.cache, key)
		h.cacheLock.Unlock()
		return nil
	}
	// Return a copy to avoid races
	return e.msg.Copy()
}

// putCache inserts response into cache with TTL from message (minimum default)
func (h *DNSHandler) putCache(q dns.Question, m *dns.Msg) {
	if !h.cfg.Cache.Enabled || m == nil || len(m.Answer) == 0 {
		return
	}
	// compute TTL as min of answers' TTLs
	ttl := uint32(h.cfg.Cache.DefaultTTL)
	min := uint32(0)
	for _, rr := range m.Answer {
		if min == 0 || rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	if min > 0 {
		ttl = int(min)
	}
	key := cacheKey(q)

	e := cacheEntry{
		msg:    m.Copy(),
		expire: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	h.cacheLock.Lock()
	if len(h.cache) >= h.cMax {
		// naive eviction: clear half (simple) to avoid memory blowups
		// production: replace with sharded LRU
		clear := h.cMax / 2
		count := 0
		for k := range h.cache {
			delete(h.cache, k)
			count++
			if count >= clear {
				break
			}
		}
	}
	h.cache[key] = e
	h.cacheLock.Unlock()
}

// forwardToUpstreams forwards the msg to configured upstreams (primary list then fallbacks) and returns response or error.
// it respects EDNS and DO bit by copying request and preserving OPT.
// tries primaries in order with client timeout; on error it tries fallbacks.
func (h *DNSHandler) forwardToUpstreams(req *dns.Msg) (*dns.Msg, error) {
	tryList := append([]string{}, h.upstreams...)
	tryList = append(tryList, h.fallbacks...)
	if len(tryList) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}

	// make a copy of the request (don't mutate caller's)
	copyReq := req.Copy()

	// preserve DO/EDNS0 present in incoming request by ensuring OPT is present as copy
	opt := req.IsEdns0()
	if opt != nil {
		copyReq.SetEdns0(opt.UDPSize(), opt.Do())
	}

	// try each upstream until success
	var lastErr error
	for _, up := range tryList {
		c := h.client
		c.Net = "udp"
		c.Timeout = time.Duration(h.cfg.ClientTimeoutMs) * time.Millisecond

		resp, _, err := c.Exchange(copyReq, up)
		if err == nil && resp != nil {
			// If upstream truncated and provides TC bit, try over TCP
			if resp.Truncated {
				tcClient := &dns.Client{
					Net:     "tcp",
					Timeout: time.Duration(h.cfg.ClientTimeoutMs) * time.Millisecond,
				}
				resp2, _, err2 := tcClient.Exchange(copyReq, up)
				if err2 == nil && resp2 != nil {
					return resp2, nil
				}
				lastErr = err2
				continue
			}
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all upstreams failed, last err: %v", lastErr)
}

// ServeDNS is the dns.Handler implementation
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	// Always support TCP fallback and proper response
	if req == nil || len(req.Question) == 0 {
		_ = w.Close()
		return
	}
	q := req.Question[0]

	// Check static first
	staticRRs := h.lookupStatic(q.Name, q.Qtype)
	if len(staticRRs) > 0 {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.RecursionAvailable = false
		// Add answers
		for _, rr := range staticRRs {
			// ensure TTL isn't negative etc
			hdr := rr.Header()
			if hdr.Ttl == 0 {
				// enforce a minimum TTL
				hdr.Ttl = 60
			}
			m.Answer = append(m.Answer, rr)
		}
		// If static has DNSKEY/RRSIG as separate names (e.g., zone signing resources),
		// they should be present in static map keyed by their owner name; include them in Additional/Authority sections if appropriate.
		// We'll append any static records for the queried name that are NOT exactly qtype (useful for DNSSEC RRs).
		// Write response
		_ = w.WriteMsg(m)
		// Logging minimal
		_ = start
		return
	}

	// Not static: try cache
	if cached := h.tryCache(q); cached != nil {
		// copy question/question id from original
		cached.Id = req.Id
		_ = w.WriteMsg(cached)
		return
	}

	// forward to upstreams
	resp, err := h.forwardToUpstreams(req)
	if err != nil {
		// return SERVFAIL
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		fmt.Fprintf(os.Stderr, "forward error for %s: %v\n", q.Name, err)
		return
	}

	// cache response (if successful and answers present)
	if resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		h.putCache(q, resp)
	}
	// Set ID to incoming query id before writing
	resp.Id = req.Id

	// Some upstreams set AA/RA etc; we simply pass-through.
	_ = w.WriteMsg(resp)
}

// Run starts the servers (UDP & TCP)
func (h *DNSHandler) Run(ctx context.Context) error {
	// handler
	dns.HandleFunc(".", h.ServeDNS)

	// UDP server
	udpAddr := h.cfg.Listen.UDP
	tcpAddr := h.cfg.Listen.TCP
	if udpAddr == "" {
		udpAddr = "0.0.0.0:53"
	}
	if tcpAddr == "" {
		tcpAddr = "0.0.0.0:53"
	}

	udpServer := &dns.Server{Addr: udpAddr, Net: "udp", Handler: dns.DefaultServeMux, UDPSize: 65535}
	tcpServer := &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: dns.DefaultServeMux}

	errCh := make(chan error, 2)

	go func() {
		fmt.Printf("starting UDP server %s\n", udpAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("udp server stopped: %w", err)
		}
	}()

	go func() {
		fmt.Printf("starting TCP server %s\n", tcpAddr)
		if err := tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("tcp server stopped: %w", err)
		}
	}()

	// Wait until context cancel or server error
	select {
	case <-ctx.Done():
		// Shutdown gracefully
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
		return nil
	case err := <-errCh:
		return err
	}
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config yaml")
	csvPath := flag.String("csv", "", "path to csv (overrides config csv)")
	flag.Parse()

	// load config
	h := &DNSHandler{
		static: make(map[string][]dns.RR),
		cache:  make(map[string]cacheEntry),
	}
	if err := h.loadConfig(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	if *csvPath != "" {
		h.cfg.CSV = *csvPath
	}
	if h.cfg.CSV != "" {
		if err := h.loadCSV(h.cfg.CSV); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load csv: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("loaded static CSV %s records: %d\n", h.cfg.CSV, len(h.static))
	}

	// init client if nil
	if h.client == nil {
		h.client = &dns.Client{Net: "udp", Timeout: time.Duration(h.cfg.ClientTimeoutMs) * time.Millisecond}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := h.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}