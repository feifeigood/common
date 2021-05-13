package core

import (
	"errors"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Reader interface {
	Read([]byte, int) (int, error)
}

type Writer interface {
	// Write packets to tun device
	Write([]byte, int) (int, error)
}

// Handler is for handling incoming TCP and UDP connections
type Handler interface {
	Handle(*TCPConn)
	HandlePacket(*UDPPacket)
}

type TCPConn struct {
	gonet.TCPConn
}

type UDPPacket struct {
	stack *Stack
	data  buffer.VectorisedView

	routeInfo struct {
		src tcpip.Address
		nic tcpip.NICID
		pn  tcpip.NetworkProtocolNumber
		id  stack.TransportEndpointID
	}
}

func (p *UDPPacket) Data() []byte {
	return p.data.ToView()
}

func (p *UDPPacket) Drop() {}

func (p *UDPPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(p.routeInfo.id.LocalAddress), Port: int(p.routeInfo.id.LocalPort)}
}

func (p *UDPPacket) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(p.routeInfo.id.RemoteAddress), Port: int(p.routeInfo.id.RemotePort)}
}

func (p *UDPPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	v := buffer.View(b)
	if len(v) > header.UDPMaximumPacketSize {
		return 0, errors.New((&tcpip.ErrMessageTooLong{}).String())
	}

	src, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("core.UDPPacket.WriteBack error: addr type error")
	}

	route, tcperr := p.stack.Stack.FindRoute(p.routeInfo.nic, tcpip.Address(src.IP), p.routeInfo.src, p.routeInfo.pn, false)
	if tcperr != nil {
		return 0, errors.New(tcperr.String())
	}
	defer route.Release()

	if tcperr := sendUDP(
		route,
		v.ToVectorisedView(),
		uint16(src.Port),
		p.routeInfo.id.RemotePort,
		0,    /* ttl */
		true, /* useDefaultTTL */
		0,    /* tos */
		nil,  /* owner */
		true,
	); tcperr != nil {
		return 0, errors.New((*tcperr).String())
	}

	return len(b), nil
}
