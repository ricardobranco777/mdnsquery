/* SPDX-License-Identifier: BSD-2-Clause */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

const (
	mdnsPort = 5353
)

var (
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")
)

type Entry struct {
	Name   string   `json:"name"`
	Host   string   `json:"host,omitempty"`
	Type   string   `json:"type,omitempty"`
	AddrV4 string   `json:"addr_v4,omitempty"`
	AddrV6 string   `json:"addr_v6,omitempty"`
	Port   uint16   `json:"port,omitempty"`
	TXT    []string `json:"txt,omitempty"`
}

// subscriber is a per-query registration: packets matching its filter are
// forwarded to ch. The dispatcher holds no lock while sending to ch, so ch
// must be buffered enough not to block the dispatcher.
type subscriber struct {
	qname string // normalized: lowercase, no trailing dot
	qtype uint16
	ch    chan *dns.Msg
}

// session holds long-lived sockets, persistent dispatcher goroutines, and
// the subscriber registry. Open once, reuse for all queries, close when done.
type session struct {
	v4mc     *net.UDPConn    // multicast listener: 224.0.0.251:5353
	v4tx     *net.UDPConn    // ephemeral sender:   0.0.0.0:0
	v6mc     *net.UDPConn    // multicast listener: [ff02::fb]:5353 (nil if unavailable)
	v6tx     *net.UDPConn    // ephemeral sender:   [::]:0          (nil if unavailable)
	v6ifaces []net.Interface // interfaces with an IPv6 link-local address

	mu   sync.RWMutex
	subs map[rrKey]map[*subscriber]struct{}

	done chan struct{}
	wg   sync.WaitGroup
}

// rrKey is a normalized (lowercase, no trailing dot) name + type pair.
type rrKey struct {
	name  string
	qtype uint16
}

// msgKeys extracts the set of rrKeys present in m's Answer and Extra sections.
// Called once per packet, before taking any lock.
func msgKeys(m *dns.Msg) map[rrKey]struct{} {
	keys := make(map[rrKey]struct{}, len(m.Answer)+len(m.Extra))
	for _, rr := range m.Answer {
		if t := dns.RRToType(rr); t != dns.TypeNULL {
			name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			keys[rrKey{name, t}] = struct{}{}
		}
	}
	for _, rr := range m.Extra {
		if t := dns.RRToType(rr); t != dns.TypeNULL {
			name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			keys[rrKey{name, t}] = struct{}{}
		}
	}
	return keys
}

func ifaceHasIPv6LinkLocal(iface net.Interface) bool {
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			ip := ipnet.IP
			if ip.To4() == nil && ip.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

func upMulticastIfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, iface := range all {
		if iface.Flags&(net.FlagUp|net.FlagMulticast) == (net.FlagUp | net.FlagMulticast) {
			out = append(out, iface)
		}
	}
	return out, nil
}

// dispatch reads packets from conn forever and fans them out to all matching
// subscribers. It exits when conn is closed (via session.Close).
func (s *session) dispatch(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
			default:
				logger.Printf("dispatch: %v", err)
			}
			return
		}
		msg := new(dns.Msg)
		msg.Data = make([]byte, n)
		copy(msg.Data, buf[:n])
		if msg.Unpack() != nil {
			continue
		}
		// Extract (name, type) keys once, before taking the lock.
		keys := msgKeys(msg)

		s.mu.RLock()
		for k := range keys {
			for sub := range s.subs[k] {
				select {
				case sub.ch <- msg:
				default: // subscriber too slow; drop rather than block dispatcher
				}
			}
		}
		s.mu.RUnlock()
	}
}

func (s *session) subscribe(qname string, qtype uint16) *subscriber {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	key := rrKey{qname, qtype}

	sub := &subscriber{
		qname: qname,
		qtype: qtype,
		ch:    make(chan *dns.Msg, 64),
	}

	s.mu.Lock()
	m := s.subs[key]
	if m == nil {
		m = make(map[*subscriber]struct{})
		s.subs[key] = m
	}
	m[sub] = struct{}{}
	s.mu.Unlock()

	return sub
}

func (s *session) unsubscribe(sub *subscriber) {
	key := rrKey{sub.qname, sub.qtype}

	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.subs[key]
	if m == nil {
		return
	}
	delete(m, sub)
	if len(m) == 0 {
		delete(s.subs, key)
	}
}

func newSession() (*session, error) {
	ifaces, err := upMulticastIfaces()
	if err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}

	s := &session{
		done: make(chan struct{}),
		subs: make(map[rrKey]map[*subscriber]struct{}),
	}

	for _, iface := range ifaces {
		if ifaceHasIPv6LinkLocal(iface) {
			s.v6ifaces = append(s.v6ifaces, iface)
		}
	}

	// IPv4 multicast listener
	// Bind to 224.0.0.251:5353 - avahi holds 0.0.0.0:5353, not the group
	// address, so this succeeds without SO_REUSEPORT.
	s.v4mc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: mdnsGroupIPv4, Port: mdnsPort})
	if err != nil {
		return nil, fmt.Errorf("udp4 mc listen: %w", err)
	}
	p4 := ipv4.NewPacketConn(s.v4mc)
	for _, iface := range ifaces {
		if err := p4.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
			return nil, err
		}
	}
	if err := p4.SetMulticastLoopback(true); err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go s.dispatch(s.v4mc)

	// IPv4 ephemeral sender
	s.v4tx, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		s.v4mc.Close()
		return nil, fmt.Errorf("udp4 tx listen: %w", err)
	}
	s.wg.Add(1)
	go s.dispatch(s.v4tx)

	// IPv6 multicast listener
	// Bind to [ff02::fb]:5353 - avahi holds [::]:5353, not the group address,
	// so this succeeds without SO_REUSEPORT, same trick as IPv4.
	s.v6mc, err = net.ListenUDP("udp6", &net.UDPAddr{IP: mdnsGroupIPv6, Port: mdnsPort})
	if err != nil {
		logger.Printf("udp6 mc listen: %v (skipping IPv6)", err)
	} else {
		p6 := ipv6.NewPacketConn(s.v6mc)
		for _, iface := range s.v6ifaces {
			if err := p6.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
				return nil, err
			}
		}
		if err := p6.SetMulticastLoopback(true); err != nil {
			return nil, err
		}
		s.wg.Add(1)
		go s.dispatch(s.v6mc)

		// IPv6 ephemeral sender
		// Bind to [::]:0 - send once per interface with Zone set,
		// which is required for link-local multicast (ff02::fb).
		s.v6tx, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			logger.Printf("udp6 tx listen: %v", err)
		} else {
			s.wg.Add(1)
			go s.dispatch(s.v6tx)
		}
	}

	return s, nil
}

func (s *session) Close() {
	close(s.done)
	// Closing all sockets unblocks all dispatch goroutines.
	s.v4mc.Close()
	s.v4tx.Close()
	if s.v6mc != nil {
		s.v6mc.Close()
	}
	if s.v6tx != nil {
		s.v6tx.Close()
	}
	s.wg.Wait()
}

func newMsgBuf(question string, qtype uint16) ([]byte, error) {
	msg := dns.NewMsg(question, qtype)
	msg.RecursionDesired = false
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	return msg.Data, nil
}

// query sends an mDNS question and collects responses until 500ms of silence
// or the hard deadline, whichever comes first. Concurrent queries are safe -
// each gets its own subscriber channel.
func (s *session) query(question string, qtype uint16, timeout time.Duration) ([]dns.RR, error) {
	wire, err := newMsgBuf(question, qtype)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	sub := s.subscribe(question, qtype)
	defer s.unsubscribe(sub)

	// Send the question over IPv4 and (if available) per-interface IPv6.
	if _, err := s.v4tx.WriteToUDP(wire, &net.UDPAddr{IP: mdnsGroupIPv4, Port: mdnsPort}); err != nil {
		logger.Printf("ipv4 send: %v", err)
	}
	if s.v6tx != nil {
		for _, iface := range s.v6ifaces {
			dst := &net.UDPAddr{IP: mdnsGroupIPv6, Port: mdnsPort, Zone: iface.Name}
			if _, err := s.v6tx.WriteToUDP(wire, dst); err != nil {
				logger.Printf("ipv6 send on %s: %v", iface.Name, err)
			}
		}
	}

	// Collect responses until 500ms of silence or hard deadline.
	const idleTimeout = 500 * time.Millisecond
	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()
	hard := time.NewTimer(timeout)
	defer hard.Stop()

	var rrs []dns.RR
	for {
		select {
		case msg := <-sub.ch:
			rrs = append(rrs, msg.Answer...)
			rrs = append(rrs, msg.Extra...)
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleTimeout)

		case <-idle.C:
			return deduplicateRRs(rrs), nil

		case <-hard.C:
			return deduplicateRRs(rrs), nil
		}
	}
}

func deduplicateRRs(rrs []dns.RR) []dns.RR {
	seen := make(map[string]struct{}, len(rrs))
	out := rrs[:0]
	for _, rr := range rrs {
		k := rr.String()
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			out = append(out, rr)
		}
	}
	return out
}

func filterTXT(txt []string) []string {
	out := make([]string, 0, len(txt))
	for _, s := range txt {
		// Skip empty strings and bare "=" (empty key, empty value).
		if s == "" || s == "=" {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func browseServiceTypes(s *session, timeout time.Duration) ([]string, error) {
	rrs, err := s.query("_services._dns-sd._udp.local.", dns.TypePTR, timeout)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(rrs))
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok {
			svc := strings.TrimSuffix(strings.TrimSuffix(ptr.Ptr, "."), ".local")
			if svc != "" {
				seen[svc] = struct{}{}
				if _, after, ok := strings.Cut(svc, "._sub."); ok {
					seen[after] = struct{}{}
				}
			}
		}
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	return types, nil
}

func resolveServiceType(s *session, svcType string, timeout time.Duration) ([]Entry, error) {
	rrs, err := s.query(svcType+".local.", dns.TypePTR, timeout)
	if err != nil {
		return nil, err
	}

	type host struct {
		name   string
		addrV4 string
		addrV6 string
	}
	type instance struct {
		entry Entry
		host  *host
	}

	instances := make(map[string]*instance) // instance FQDN -> instance
	hosts := make(map[string]*host)         // host FQDN -> host

	// getHost returns the host entry for the given FQDN, creating it if needed.
	getHost := func(fqdn string) *host {
		h, ok := hosts[fqdn]
		if !ok {
			h = &host{name: strings.TrimSuffix(fqdn, ".")}
			hosts[fqdn] = h
		}
		return h
	}

	for _, rr := range rrs {
		switch r := rr.(type) {

		// PTR -> create instance
		case *dns.PTR:
			if _, ok := instances[r.Ptr]; !ok {
				instances[r.Ptr] = &instance{
					entry: Entry{
						Name: strings.TrimSuffix(r.Ptr, "."),
						Type: svcType,
					},
				}
			}

		// SRV -> bind instance to host
		case *dns.SRV:
			inst, ok := instances[r.Hdr.Name]
			if !ok {
				continue
			}
			h := getHost(r.Target)
			inst.entry.Host = h.name
			inst.entry.Port = r.Port
			inst.host = h

		// TXT -> attach directly to instance
		case *dns.TXT:
			if inst, ok := instances[r.Hdr.Name]; ok {
				inst.entry.TXT = filterTXT(r.Txt)
			}

		// A -> update host (created eagerly so A before SRV is handled)
		case *dns.A:
			h := getHost(r.Hdr.Name)
			if h.addrV4 == "" {
				h.addrV4 = r.A.String()
			}

		// AAAA -> update host
		case *dns.AAAA:
			h := getHost(r.Hdr.Name)
			if h.addrV6 == "" {
				h.addrV6 = r.AAAA.String()
			}
		}
	}

	// Finalize: copy host addresses into each instance entry.
	out := make([]Entry, 0, len(instances))
	for _, inst := range instances {
		if inst.host != nil {
			inst.entry.AddrV4 = inst.host.addrV4
			inst.entry.AddrV6 = inst.host.addrV6
		}
		out = append(out, inst.entry)
	}
	return out, nil
}

func main() {
	sess, err := newSession()
	if err != nil {
		logger.Fatalf("open session: %v", err)
	}
	defer sess.Close()

	serviceTypes, err := browseServiceTypes(sess, 5*time.Second)
	if err != nil {
		logger.Fatalf("browse types: %v", err)
	}
	if len(serviceTypes) == 0 {
		logger.Fatal("no service types found")
	}

	var (
		mu         sync.Mutex
		allEntries []Entry
		dedup      = map[string]struct{}{}
		wg         sync.WaitGroup
	)

	// Resolve all service types concurrently - queries are independent
	// and the dispatcher fans packets to each subscriber channel.
	for _, svcType := range serviceTypes {
		wg.Go(func() {
			entries, err := resolveServiceType(sess, svcType, 3*time.Second)
			if err != nil {
				logger.Printf("resolve %s: %v", svcType, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, e := range entries {
				key := fmt.Sprintf("%s|%d", e.Name, e.Port)
				if _, dup := dedup[key]; !dup {
					dedup[key] = struct{}{}
					allEntries = append(allEntries, e)
				}
			}
		})
	}
	wg.Wait()

	sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].Name < allEntries[j].Name })

	out, err := json.MarshalIndent(allEntries, "", "  ")
	if err != nil {
		logger.Fatalf("marshal: %v", err)
	}
	fmt.Println(string(out))
}
