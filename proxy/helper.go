package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"

	"github.com/chentanyi/cloudflare-worker-proxy/cert"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("at", "proxy")
)

type Options struct {
	Target      string
	Password    string
	CA          *cert.CA
	SslInsecure bool

	httpsDail func(ctx context.Context, network, address string) (net.Conn, error)
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
