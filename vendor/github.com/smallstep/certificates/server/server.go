package server

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
)

// ServerShutdownTimeout is the default time to wait before closing
// connections on shutdown.
const ServerShutdownTimeout = 60 * time.Second

// Server is a incomplete component that implements a basic HTTP/HTTPS
// server.
type Server struct {
	*http.Server
	listener   *net.TCPListener
	reloadCh   chan net.Listener
	shutdownCh chan struct{}
}

// New creates a new HTTP/HTTPS server configured with the passed
// address, http.Handler and tls.Config.
func New(addr string, handler http.Handler, tlsConfig *tls.Config) *Server {
	return &Server{
		reloadCh:   make(chan net.Listener),
		shutdownCh: make(chan struct{}),
		Server:     newHTTPServer(addr, handler, tlsConfig),
	}
}

// newHTTPServer creates a new http.Server with the TCP address, handler and
// tls.Config.
func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		TLSConfig:    tlsConfig,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		ErrorLog:     log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Llongfile),
	}
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming connections.
func (srv *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}

	return srv.Serve(ln)
}

// Serve runs Serve or ServeTLS on the underlying http.Server and listen to
// channels to reload or shutdown the server.
func (srv *Server) Serve(ln net.Listener) error {
	var err error
	// Store the current listener.
	// In reloads we'll create a copy of the underlying os.File so the close of the server one does not affect the copy.
	srv.listener = ln.(*net.TCPListener)

	for {
		// Start server
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			log.Printf("Serving HTTP on %s ...", srv.Addr)
			err = srv.Server.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
		} else {
			log.Printf("Serving HTTPS on %s ...", srv.Addr)
			err = srv.Server.ServeTLS(tcpKeepAliveListener{ln.(*net.TCPListener)}, "", "")
		}

		// log unexpected errors
		if err != http.ErrServerClosed {
			log.Println(errors.Wrap(err, "unexpected error"))
		}

		select {
		case ln = <-srv.reloadCh:
			srv.listener = ln.(*net.TCPListener)
		case <-srv.shutdownCh:
			return http.ErrServerClosed
		}
	}
}

// Shutdown gracefully shuts down the server without interrupting any active
// connections.
func (srv *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
	defer cancel()              // release resources if Shutdown ends before the timeout
	defer close(srv.shutdownCh) // close shutdown channel
	return srv.Server.Shutdown(ctx)
}

func (srv *Server) reloadShutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
	defer cancel() // release resources if Shutdown ends before the timeout
	return srv.Server.Shutdown(ctx)
}

// Reload reloads the current server with the configuration of the passed
// server.
func (srv *Server) Reload(ns *Server) error {
	var err error
	var ln net.Listener

	if srv.Addr != ns.Addr {
		// Open new address
		ln, err = net.Listen("tcp", ns.Addr)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		// Get a copy of the underlying os.File
		fd, err := srv.listener.File()
		if err != nil {
			return errors.WithStack(err)
		}
		// Make sure to close the copy
		defer fd.Close()

		// Creates a new listener copying fd
		ln, err = net.FileListener(fd)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Close old server without sending a signal
	if err := srv.reloadShutdown(); err != nil {
		return err
	}

	// Update old server
	srv.Server = ns.Server
	srv.reloadCh <- ln
	return nil
}

// Forbidden writes on the http.ResponseWriter a text/plain forbidden
// response.
func (srv *Server) Forbidden(w http.ResponseWriter) {
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Content-Length", "11")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Forbidden.\n"))
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
