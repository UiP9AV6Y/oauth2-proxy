package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// Server represents an HTTP or HTTPS server.
type Server interface {
	// Start blocks and runs the server.
	Start(ctx context.Context) error
}

// Opts contains the information required to set up the server.
type Opts struct {
	// Handler is the http.Handler to be used to serve http pages by the server.
	Handler http.Handler

	// HTTPAddress is the address the HTTP server should listen on.
	HTTPAddress string

	// HTTPSAddress is the address the HTTPS server should listen on.
	HTTPSAddress string

	// TLSCertFile is the filename of the certificate file for the HTTPS server.
	TLSCertFile string

	// TLSKeyFile is the filename of the key file for the HTTPS server.
	TLSKeyFile string
}

// NewServer creates a new Server from the options given.
func NewServer(opts Opts) (Server, error) {
	s := &server{
		handler: opts.Handler,
	}
	if err := s.setupListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up listener: %v", err)
	}
	if err := s.setupTLSListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up TLS listener: %v", err)
	}

	return s, nil
}

// server is an implementation of the Server interface.
type server struct {
	handler http.Handler

	listener    net.Listener
	tlsListener net.Listener
}

// setupListener sets the server listener if the HTTP server is enabled.
// The HTTP server can be disabled by setting the HTTPAddress to "-" or by
// leaving it empty.
func (s *server) setupListener(opts Opts) error {
	if opts.HTTPAddress == "" || opts.HTTPAddress == "-" {
		// No HTTP listener required
		return nil
	}

	networkType := getNetworkScheme(opts.HTTPAddress)
	listenAddr := getListenAddress(opts.HTTPAddress)

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		return fmt.Errorf("listen (%s, %s) failed: %v", networkType, listenAddr, err)
	}
	s.listener = listener

	return nil
}

// setupTLSListener sets the server TLS listener if the HTTPS server is enabled.
// The HTTPS server can be disabled by setting the HTTPSAddress to "-" or by
// leaving it empty.
func (s *server) setupTLSListener(opts Opts) error {
	if opts.HTTPSAddress == "" || opts.HTTPSAddress == "-" {
		// No HTTPS listener required
		return nil
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("could not load TLS certificates (%s, %s): %v", opts.TLSCertFile, opts.TLSKeyFile, err)
	}
	config.Certificates = []tls.Certificate{cert}

	listener, err := net.Listen("tcp", opts.HTTPSAddress)
	if err != nil {
		return fmt.Errorf("listen (%s) failed: %v", opts.HTTPSAddress, err)
	}

	s.tlsListener = tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, config)
	return nil
}

// Start starts the HTTP and HTTPS server if applicable.
// It will block until the context is cancelled.
// If any errors occur, only the first error will be returned.
func (s *server) Start(ctx context.Context) error {
	g, groupCtx := errgroup.WithContext(ctx)

	if s.listener != nil {
		g.Go(func() error {
			if err := s.startServer(groupCtx, s.listener); err != nil {
				return err
			}
			return nil
		})
	}

	if s.tlsListener != nil {
		g.Go(func() error {
			if err := s.startServer(groupCtx, s.tlsListener); err != nil {
				return err
			}
			return nil
		})
	}

	return g.Wait()
}

// startServer creates and starts a new server with the given listener.
// When the given context is cancelled the server will be shutdown.
// If any errors occur, only the first error will be returned.
func (s *server) startServer(ctx context.Context, listener net.Listener) error {
	srv := &http.Server{Handler: s.handler}
	g, groupCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-groupCtx.Done()

		if err := srv.Shutdown(context.Background()); err != nil {
			return err
		}
		return nil
	})

	g.Go(func() error {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("could not start server: %v", err)
		}
		return nil
	})

	return g.Wait()
}

// getNetworkScheme gets the scheme for the HTTP server.
func getNetworkScheme(addr string) string {
	var scheme string
	i := strings.Index(addr, "://")
	if i > -1 {
		scheme = addr[0:i]
	}

	switch scheme {
	case "", "http":
		return "tcp"
	default:
		return scheme
	}
}

// getListenAddress gets the address for the HTTP server.
func getListenAddress(addr string) string {
	slice := strings.SplitN(addr, "//", 2)
	return slice[len(slice)-1]
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by so that dead TCP connections (e.g. closing laptop
// mid-download) eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept implements the TCPListener interface.
// It sets the keep alive period to 3 minutes for each connection.
func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		logger.Printf("Error setting Keep-Alive: %v", err)
	}
	err = tc.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		logger.Printf("Error setting Keep-Alive period: %v", err)
	}
	return tc, nil
}
