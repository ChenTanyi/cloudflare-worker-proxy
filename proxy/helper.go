package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("at", "proxy")
)

type Options struct {
	Target      string
	Password    string
	CA          CA
	SslInsecure bool
	TCPListen   func() (net.Listener, error)

	httpsDail func(ctx context.Context, network, address string) (net.Conn, error)
}

type CA interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func WriteResponse(w http.ResponseWriter, status int, message string) {
	log.Error(message)
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func execute(done chan struct{}, function func()) {
	function()

	if done != nil {
		done <- struct{}{}
	}
}

func copy(dst io.Writer, src io.Reader, message string, done chan struct{}) {
	execute(done, func() {
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Debugf("io.Copy [%s]: %v", message, err)
			return
		}
	})
}

func readBuf(dst io.Writer, buf *bufio.Reader, message string) {
	buffered := int64(buf.Buffered())
	n, err := io.CopyN(dst, buf, buffered)
	if err != nil || n < buffered {
		log.Errorf("Copy buf [%s]: %v", message, err)
	}
}

func fixupTarget(target string) string {
	if target == "" {
		return ""
	}

	if !(strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
		target = "https://" + target
	}
	if !strings.HasSuffix(target, "/") {
		target = target + "/"
	}
	return target
}
