package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type ForwardingRule struct {
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}

type Config struct {
	Rules []ForwardingRule `json:"rules"`
}

type DNSCacheEntry struct {
	IP        net.IP
	UpdatedAt time.Time
}

type DNSCache struct {
	mu       sync.RWMutex
	entries  map[string]DNSCacheEntry
	resolver *net.Resolver
}

type Forwarder struct {
	config    Config
	listeners []net.Listener
	dnsCache  *DNSCache
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

func main() {
	var initConfig = flag.Bool("init", false, "Create default config.json file")
	var configFile = flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	if *initConfig {
		createDefaultConfig(*configFile)
		return
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	forwarder := NewForwarder(config)
	if err := forwarder.Start(); err != nil {
		log.Fatalf("Failed to start forwarder: %v", err)
	}

	log.Println("TCP forwarder started successfully")
	forwarder.WaitForShutdown()
}

func createDefaultConfig(filename string) {
	defaultConfig := Config{
		Rules: []ForwardingRule{
			{
				Name:       "HTTP",
				ListenPort: 80,
				TargetHost: "mail.example.com", // Replace with your mail server hostname or IP
				TargetPort: 80,
			},
			{
				Name:       "HTTPS",
				ListenPort: 443,
				TargetHost: "mail.example.com", // Replace with your mail server hostname or IP
				TargetPort: 443,
			},
			{
				Name:       "SMTP",
				ListenPort: 587,
				TargetHost: "mail.example.com", // Replace with your mail server hostname or IP
				TargetPort: 587,
			},
			{
				Name:       "IMAPS",
				ListenPort: 993,
				TargetHost: "mail.example.com", // Replace with your mail server hostname or IP
				TargetPort: 993,
			},
		},
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal default config: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Fatalf("Failed to write config file: %v", err)
	}

	fmt.Printf("Default configuration created at %s\n", filename)
	fmt.Println("Please edit the target_host values to match your target server hostname or IP")
	fmt.Println("Examples:")
	fmt.Println("  - Hostname: \"mail.company.com\"")
	fmt.Println("  - Direct IP: \"192.168.1.100\"")
	fmt.Println("  - VPN hostname: \"internal-server\"")
	fmt.Println("")
	fmt.Println("The forwarder automatically detects hostnames vs IPs and uses DNS caching for hostnames.")
}

func loadConfig(filename string) (Config, error) {
	var config Config

	data, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		entries: make(map[string]DNSCacheEntry),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 5,
				}
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

func (d *DNSCache) resolveHost(ctx context.Context, hostname string) (net.IP, error) {
	ips, err := d.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for hostname %s", hostname)
	}
	return ips[0].IP, nil
}

func (d *DNSCache) updateEntry(hostname string, ip net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()

	oldEntry, existed := d.entries[hostname]
	d.entries[hostname] = DNSCacheEntry{
		IP:        ip,
		UpdatedAt: time.Now(),
	}

	if !existed {
		log.Printf("DNS: Resolved %s -> %s", hostname, ip)
	} else if !oldEntry.IP.Equal(ip) {
		log.Printf("DNS: IP changed for %s: %s -> %s", hostname, oldEntry.IP, ip)
	}
}

func (d *DNSCache) getIP(hostname string) (net.IP, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	entry, exists := d.entries[hostname]
	if !exists {
		return nil, false
	}

	// Consider cache stale after 2 hours for emergency fallback
	if time.Since(entry.UpdatedAt) > 2*time.Hour {
		log.Printf("DNS: Cache entry for %s is stale (age: %v)", hostname, time.Since(entry.UpdatedAt))
		return entry.IP, false
	}

	return entry.IP, true
}

func (d *DNSCache) getIPWithFallback(ctx context.Context, hostname string) (net.IP, error) {
	// Try cache first
	if ip, valid := d.getIP(hostname); valid {
		return ip, nil
	}

	// Cache miss or stale - resolve fresh
	log.Printf("DNS: Resolving %s (cache miss or stale)", hostname)
	ip, err := d.resolveHost(ctx, hostname)
	if err != nil {
		// If fresh resolution fails, try stale cache as fallback
		if ip, exists := d.getIP(hostname); exists {
			log.Printf("DNS: Fresh resolution failed for %s, using stale cache entry: %s", hostname, ip)
			return ip, nil
		}
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", hostname, err)
	}

	d.updateEntry(hostname, ip)
	return ip, nil
}

func NewForwarder(config Config) *Forwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &Forwarder{
		config:   config,
		dnsCache: NewDNSCache(),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (f *Forwarder) Start() error {
	// Pre-resolve all hostnames on startup
	uniqueHosts := make(map[string]bool)
	for _, rule := range f.config.Rules {
		if net.ParseIP(rule.TargetHost) == nil {
			uniqueHosts[rule.TargetHost] = true
		}
	}

	for hostname := range uniqueHosts {
		log.Printf("DNS: Resolving %s on startup...", hostname)
		ip, err := f.dnsCache.resolveHost(f.ctx, hostname)
		if err != nil {
			log.Printf("DNS: Warning - failed to resolve %s on startup: %v", hostname, err)
			continue
		}
		f.dnsCache.updateEntry(hostname, ip)
	}

	// Start periodic DNS refresh
	f.wg.Add(1)
	go f.periodicDNSRefresh()

	for _, rule := range f.config.Rules {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rule.ListenPort))
		if err != nil {
			f.cleanup()
			return fmt.Errorf("failed to listen on port %d for rule %s: %w", rule.ListenPort, rule.Name, err)
		}

		f.listeners = append(f.listeners, listener)
		log.Printf("Started listener for %s on port %d -> %s:%d", rule.Name, rule.ListenPort, rule.TargetHost, rule.TargetPort)

		f.wg.Add(1)
		go f.handleListener(listener, rule)
	}

	return nil
}

func (f *Forwarder) periodicDNSRefresh() {
	defer f.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Printf("DNS: Started periodic refresh (every 1 hour)")

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.refreshAllDNS()
		}
	}
}

func (f *Forwarder) refreshAllDNS() {
	uniqueHosts := make(map[string]bool)
	for _, rule := range f.config.Rules {
		if net.ParseIP(rule.TargetHost) == nil {
			uniqueHosts[rule.TargetHost] = true
		}
	}

	log.Printf("DNS: Refreshing %d hostnames...", len(uniqueHosts))

	for hostname := range uniqueHosts {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		ip, err := f.dnsCache.resolveHost(f.ctx, hostname)
		if err != nil {
			log.Printf("DNS: Failed to refresh %s: %v", hostname, err)
			continue
		}
		f.dnsCache.updateEntry(hostname, ip)
	}

	log.Printf("DNS: Refresh cycle completed")
}

func (f *Forwarder) handleListener(listener net.Listener, rule ForwardingRule) {
	defer f.wg.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-f.ctx.Done():
				return
			default:
				log.Printf("Failed to accept connection for %s: %v", rule.Name, err)
				continue
			}
		}

		f.wg.Add(1)
		go f.handleConnection(conn, rule)
	}
}

func (f *Forwarder) handleConnection(clientConn net.Conn, rule ForwardingRule) {
	defer f.wg.Done()
	defer func() {
		if err := clientConn.Close(); err != nil {
			log.Printf("Error closing client connection: %v", err)
		}
	}()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("New connection from %s for %s", clientAddr, rule.Name)

	// Enable TCP keepalive
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			log.Printf("Failed to set keepalive on client connection: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			log.Printf("Failed to set keepalive period on client connection: %v", err)
		}
	}

	// Resolve target address using DNS cache
	var targetAddr string
	if net.ParseIP(rule.TargetHost) != nil {
		// Target is already an IP address
		targetAddr = net.JoinHostPort(rule.TargetHost, fmt.Sprintf("%d", rule.TargetPort))
	} else {
		// Target is a hostname - resolve via DNS cache
		ip, err := f.dnsCache.getIPWithFallback(f.ctx, rule.TargetHost)
		if err != nil {
			log.Printf("Failed to resolve %s for %s from %s: %v", rule.TargetHost, rule.Name, clientAddr, err)
			return
		}
		targetAddr = net.JoinHostPort(ip.String(), fmt.Sprintf("%d", rule.TargetPort))
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s for %s from %s: %v", targetAddr, rule.Name, clientAddr, err)
		return
	}
	defer func() {
		if err := targetConn.Close(); err != nil {
			log.Printf("Error closing target connection: %v", err)
		}
	}()

	// Enable TCP keepalive on target connection
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			log.Printf("Failed to set keepalive on target connection: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			log.Printf("Failed to set keepalive period on target connection: %v", err)
		}
	}

	log.Printf("Established connection: %s -> %s (%s)", clientAddr, targetAddr, rule.Name)

	var wg sync.WaitGroup
	wg.Add(2)

	// Use channels to signal when each direction completes
	done := make(chan struct{})

	go f.copyData(clientConn, targetConn, &wg, fmt.Sprintf("%s->%s (%s)", clientAddr, targetAddr, rule.Name), done)
	go f.copyData(targetConn, clientConn, &wg, fmt.Sprintf("%s->%s (%s)", targetAddr, clientAddr, rule.Name), done)

	wg.Wait()
	close(done)
	log.Printf("Connection closed: %s -> %s (%s)", clientAddr, targetAddr, rule.Name)
}

func (f *Forwarder) copyData(src, dst net.Conn, wg *sync.WaitGroup, direction string, done chan struct{}) {
	defer wg.Done()

	buffer := make([]byte, 32*1024)

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-done:
			return
		default:
		}

		// Increase timeout to 5 minutes for long-polling support (Exchange OWA)
		if err := src.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("Failed to set read deadline in %s: %v", direction, err)
			return
		}
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				// Check if it's a timeout error - those are normal for idle connections
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout on read - connection is idle, close gracefully
					return
				}
				log.Printf("Read error in %s: %v", direction, err)
			}
			// EOF or error - just return and let deferred cleanup handle connection close
			return
		}

		if n > 0 {
			if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				log.Printf("Failed to set write deadline in %s: %v", direction, err)
				return
			}
			written, err := dst.Write(buffer[:n])
			if err != nil {
				log.Printf("Write error in %s: %v", direction, err)
				return
			}
			if written != n {
				log.Printf("Short write in %s: wrote %d of %d bytes", direction, written, n)
				return
			}
		}
	}
}

func (f *Forwarder) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received, stopping forwarder...")

	f.cancel()
	f.cleanup()
	f.wg.Wait()

	log.Println("TCP forwarder stopped gracefully")
}

func (f *Forwarder) cleanup() {
	for _, listener := range f.listeners {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}
}
