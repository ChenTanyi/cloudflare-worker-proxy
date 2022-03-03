package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	PASSWORD_HEADER = "x-fetch-password"
)

type HTTPProxyHandler struct {
	httpHandler http.Handler
	httpsDial   func(ctx context.Context, network, address string) (net.Conn, error)
}

func NewHTTPProxyHandler(options *Options) *HTTPProxyHandler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if options.SslInsecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	p := &HTTPProxyHandler{
		httpHandler: &httputil.ReverseProxy{
			Transport: transport,
			Director: func(r *http.Request) {
				director(options.Target, options.Password, r)
			},
		},
		httpsDial: options.httpsDail,
	}

	return p
}

func (p *HTTPProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.ToUpper(r.Method) == http.MethodConnect {
		p.Connect(w, r)
		return
	}

	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	log.Infof("ServeHTTP %s %s://%s", r.Method, r.URL.Scheme, r.URL.Host)
	if p.httpHandler == nil {
		p.httpHandler = &httputil.ReverseProxy{}
	}
	p.httpHandler.ServeHTTP(w, r)
	log.Debugf("ServeHTTP %s %s://%s done", r.Method, r.URL.Scheme, r.URL.Host)
}

func (p *HTTPProxyHandler) Connect(w http.ResponseWriter, r *http.Request) {
	log.Infof("Connect %s", r.Host)
	if p.httpsDial == nil {
		p.httpsDial = (&net.Dialer{}).DialContext
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		WriteResponse(w, 500, fmt.Sprintf("Hijack not support"))
		return
	}

	server, err := p.httpsDial(r.Context(), "tcp", r.Host)
	if err != nil {
		WriteResponse(w, 502, fmt.Sprintf("Connect failed to %s: %v", r.Host, err))
		return
	}
	defer server.Close()
	w.WriteHeader(200)

	client, buf, err := hijacker.Hijack()
	if err != nil {
		WriteResponse(w, 500, fmt.Sprintf("Hijack error: %v", err))
		return
	}
	defer client.Close()

	serverClosed := make(chan struct{}, 1)
	clientClosed := make(chan struct{}, 1)
	message := fmt.Sprintf("connection %s", r.Host)
	go copy(client, server, message, serverClosed)
	go func() {
		readBuf(server, buf.Reader, message)
		copy(server, client, message, clientClosed)
	}()

	select {
	case <-serverClosed:
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.SetKeepAlive(false)
			tcp.SetLinger(0) // send RST other than FIN when finished, to avoid TIME_WAIT
		}
		client.Close()
	case <-clientClosed:
		server.Close()
	}

	log.Infof("DisConnect %s", r.Host)
}

func director(target string, password string, r *http.Request) {
	if target == "" {
		return
	}
	target = target + r.URL.String()
	log.Debugf("Redirect target to %s", target)

	targetUri, err := url.Parse(target)
	if err != nil {
		log.Errorf("Unable to parse target url %s: %v", target, err)
		return
	}
	r.URL = targetUri
	r.Host = targetUri.Host

	if password != "" {
		r.Header.Set(PASSWORD_HEADER, password)
	}
}
