package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

type Server struct {
	httpServer *http.Server

	tcpListener func() (net.Listener, error)
	tlsListener net.Listener
}

func NewServer(options *Options) *Server {
	options.Target = fixupTarget(options.Target)
	var tlsListener net.Listener
	if options.CA == nil {
		options.httpsDail = (&net.Dialer{}).DialContext
	} else {
		conn := make(chan net.Conn)
		tlsListener = tls.NewListener(
			&Listener{conn},
			&tls.Config{
				GetCertificate: options.CA.GetCertificate,
			},
		)
		options.httpsDail = func(ctx context.Context, network, address string) (net.Conn, error) {
			client, server := net.Pipe()
			conn <- server
			return client, nil
		}
	}

	s := &Server{
		httpServer: &http.Server{
			Handler: NewHTTPProxyHandler(options),
		},
		tcpListener: options.TCPListen,
		tlsListener: tlsListener,
	}
	return s
}

func (s *Server) Start() chan error {
	errChan := make(chan error, 2)
	go func() {
		l, err := s.tcpListener()
		if err != nil {
			errChan <- err
			return
		}
		errChan <- s.httpServer.Serve(l)
	}()

	go func() {
		if s.tlsListener != nil {
			errChan <- s.httpServer.Serve(s.tlsListener)
		}
	}()

	return errChan
}
