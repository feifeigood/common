package netstack

import (
	"net"
)

type Conn interface {
	net.Conn
}

type Packet interface {
	Data() []byte
	WriteBack(b []byte, addr net.Addr) (n int, err error)
	Drop()
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type conn struct {
	net.Conn
}

func NewConn(nc net.Conn) Conn {
	if c, ok := nc.(Conn); ok {
		return c
	}
	return &conn{Conn: nc}
}

type Handler interface {
	Handle(Conn, net.Addr) error
	HandlePacket(Packet, net.Addr) error
}
