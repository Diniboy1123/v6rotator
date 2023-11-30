package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
)

type CLIConfig struct {
	IPv6WithPrefix string `help:"IPv6 address with prefix to use as a rotating prefix." arg:"" name:"ipv6/prefix" optional:""`
	Port           int    `help:"Port for the HTTP proxy." short:"p" default:"1337"`
	Verbose        bool   `help:"Enable verbose mode." short:"d"`
	Version        bool   `help:"Show version and exit." short:"v"`
	BindAddress    string `help:"Bind address for the HTTP proxy." default:"127.0.0.1" short:"b" type:"ip"`
	Insecure       bool   `help:"Enable access to non-HTTPS ports in CONNECT requests & to unsafe hosts." short:"i" default:"false"`
}

var httpsPorts = []int{443, 2053, 2083, 2087, 2096, 8443}
var unsafeHosts = []string{"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "[::]", "::ffff:127.0.0.1", "localhost.localdomain", "localhost.local"}

func main() {
	var cliConfig CLIConfig
	ctx := kong.Parse(&cliConfig,
		kong.Name("http-proxy-rotator"),
		kong.Description("HTTP proxy with rotating IPv6 addresses"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Summary: true,
		}),
		kong.Vars{"version": "1.0.0"},
	)

	if cliConfig.Version {
		fmt.Printf("HTTP Proxy Rotator v%s\n", ctx.Model.Vars()["version"])
		os.Exit(0)
	} else if cliConfig.IPv6WithPrefix == "" {
		log.Fatalf("Missing required argument: ipv6/prefix")
	}

	ipv6, prefix, err := parseIPv6WithPrefix(cliConfig.IPv6WithPrefix)
	if err != nil {
		log.Fatalf("Error parsing IPv6 with prefix: %v", err)
	}

	proxy := NewRotatingProxy(ipv6, prefix, cliConfig.Port, cliConfig.Verbose, cliConfig.BindAddress, cliConfig.Insecure)
	err = proxy.Start()
	if err != nil {
		log.Fatalf("Error starting HTTP proxy: %v", err)
	}
}

func parseIPv6WithPrefix(ipv6WithPrefix string) (net.IP, int, error) {
	parts := strings.Split(ipv6WithPrefix, "/")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid IPv6 with prefix. Expected format: ipv6/prefix")
	}

	ip := net.ParseIP(parts[0])
	prefixLen, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, 0, fmt.Errorf("invalid prefix length")
	}
	return ip, prefixLen, nil
}

type RotatingProxy struct {
	IPv6     net.IP
	Prefix   int
	Port     int
	Verbose  bool
	Bind     string
	Insecure bool
}

func NewRotatingProxy(ipv6 net.IP, prefix int, port int, verbose bool, bind string, insecure bool) *RotatingProxy {
	return &RotatingProxy{
		IPv6:     ipv6,
		Prefix:   prefix,
		Port:     port,
		Verbose:  verbose,
		Bind:     bind,
		Insecure: insecure,
	}
}

func (rp *RotatingProxy) Start() error {
	listenAddr := fmt.Sprintf("%s:%d", rp.Bind, rp.Port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("error listening on %s: %v", listenAddr, err)
	}
	defer ln.Close()
	fmt.Printf("Starting HTTP proxy on %s\n", listenAddr)

	server := rp.newHTTPServer(ln)
	server.IdleTimeout = 30 * time.Second

	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-interruptChan:
		log.Println("Received interrupt signal. Shutting down...")
		cancel()
	case <-ctx.Done():
	}

	log.Println("Shutting down server...")
	_ = server.Shutdown(context.Background())

	wg.Wait()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("error shutting down server: %v", err)
	}
	return nil
}

func (rp *RotatingProxy) newHTTPServer(ln net.Listener) *http.Server {
	return &http.Server{
		Handler: rp.newHTTPHandler(),
	}
}

func (rp *RotatingProxy) newHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rp.Insecure && isUnsafeHost(r.URL.Hostname()) {
			// NOTE: This is not RFC compliant since we send a Content-Length header
			// but this way we can avoid code duplication.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		newIPv6 := rp.rotateIPv6()

		if r.Method == http.MethodConnect {
			rp.handleConnect(w, r, newIPv6)
		} else {
			rp.handleHTTP(w, r, newIPv6)
		}
	})
}

func isHTTPS(port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, httpsPort := range httpsPorts {
		if portInt == httpsPort {
			return true
		}
	}
	return false
}

func isUnsafeHost(host string) bool {
	for _, unsafeHost := range unsafeHosts {
		if host == unsafeHost {
			return true
		}
	}
	return false
}

func (rp *RotatingProxy) handleConnect(w http.ResponseWriter, r *http.Request, newIPv6 net.IP) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if !rp.Insecure && !isHTTPS(r.URL.Port()) {
		_, _ = clientConn.Write([]byte("HTTP/1.1 400 Only HTTPS is supported\r\n\r\n"))
		_ = clientConn.Close()
		return
	}

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: newIPv6},
	}

	proxyConn, err := dialer.Dial("tcp", r.URL.Host)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 500 Remote connect failed\r\n\r\n"))
		_ = clientConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		_, _ = io.Copy(proxyConn, clientConn)
	}()
	go func() {
		_, _ = io.Copy(clientConn, proxyConn)
	}()
}

func (rp *RotatingProxy) handleHTTP(w http.ResponseWriter, r *http.Request, newIPv6 net.IP) {
	proxy := rp.newReverseProxy(newIPv6)
	proxy.ServeHTTP(w, r)
}

func (rp *RotatingProxy) newReverseProxy(newIPv6 net.IP) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(request *http.Request) {
			request.Host = request.URL.Host
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: newIPv6},
			}).DialContext,
			IdleConnTimeout: time.Minute,
		},
	}
}

func (rp *RotatingProxy) rotateIPv6() net.IP {
	newIPv6 := generateRandomIPv6(fmt.Sprintf("%s/%d", rp.IPv6, rp.Prefix))
	if rp.Verbose {
		log.Println(fmt.Sprintf("Rotating IPv6 address to %s", newIPv6))
	}
	return net.ParseIP(newIPv6)
}

func generateRandomIPv6(prefix string) string {
	parts := strings.Split(prefix, "/")
	if len(parts) != 2 {
		log.Fatalf("Invalid IPv6 with prefix. Expected format: ipv6/prefix")
	}

	ip := net.ParseIP(parts[0])
	prefixLen, err := strconv.Atoi(parts[1])
	if err != nil {
		log.Fatalf("Invalid prefix length")
	}

	randomIPv6, err := generateRandomIPv6InPrefix(ip, prefixLen)
	if err != nil {
		log.Fatalf("Error generating random IPv6 address: %v", err)
	}
	return randomIPv6.String()
}

func generateRandomIPv6InPrefix(ip net.IP, prefixLen int) (net.IP, error) {
	if ip.To4() != nil {
		return nil, fmt.Errorf("IPv4 address not supported")
	}

	randomIPv6 := make(net.IP, len(ip))
	copy(randomIPv6, ip)
	for i := prefixLen / 8; i < len(randomIPv6); i++ {
		randomIPv6[i] = byte(rand.Intn(256))
	}
	return randomIPv6, nil
}
