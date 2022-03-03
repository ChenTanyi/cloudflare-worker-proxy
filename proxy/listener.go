package proxy

import "net"

type Listener struct {
	conn chan net.Conn
}

func (l *Listener) Accept() (net.Conn, error) {
	return <-l.conn, nil
}

func (*Listener) Close() error   { return nil }
func (*Listener) Addr() net.Addr { return defaultInternalAddr }

var defaultInternalAddr = &interalAddr{}

type interalAddr struct{}

func (*interalAddr) Network() string {
	return "internal"
}

func (*interalAddr) String() string {
	return ""
}
