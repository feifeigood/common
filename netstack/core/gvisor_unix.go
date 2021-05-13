// +build linux darwin

package core

import (
	"github.com/feifeigood/common/bytes/pool"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is a tun-like device for reading packets from system
type Device interface {
	Reader
	Writer
	DeviceType() string
	GetMTU() int
}

type Endpoint struct {
	*channel.Endpoint
	Reader Reader
	Writer Writer

	mtu int
}

func CreateEndpoint(dev Device) stack.LinkEndpoint {
	wr, ok := dev.(Writer)
	if !ok {
		panic("invalid tun device for unix")
	}
	rr, ok := dev.(Reader)
	if !ok {
		panic("invalid tun device for unix")
	}
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(dev.GetMTU()), ""),
		Reader:   rr,
		Writer:   wr,
		mtu:      dev.GetMTU(),
	}

	ep.Endpoint.AddNotify(ep)
	return ep
}

// Attach is to attach device to stack
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	const offset = 4

	e.Endpoint.Attach(dispatcher)
	go func(r Reader, size int, ep *channel.Endpoint) {
		for {
			buf := make([]byte, size)
			nr, err := r.Read(buf, offset)
			if err != nil {
				break
			}
			buf = buf[offset:]

			switch header.IPVersion(buf) {
			case header.IPv4Version:
				ep.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: 0,
					Data:               buffer.View(buf[:nr]).ToVectorisedView(),
				}))
			case header.IPv6Version:
				ep.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: 0,
					Data:               buffer.View(buf[:nr]).ToVectorisedView(),
				}))
			}
		}
	}(e.Reader, offset+e.mtu, e.Endpoint)
}

// WriteNotify will be called when a write happens to the queue.
func (e *Endpoint) WriteNotify() {
	const offset = 4

	packet, ok := e.Endpoint.Read()
	if !ok {
		return
	}

	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf[:cap(buf)])

	var vv buffer.VectorisedView
	// Append upper headers.
	vv.AppendView(packet.Pkt.NetworkHeader().View())
	vv.AppendView(packet.Pkt.TransportHeader().View())
	// Append data payload.
	vv.Append(packet.Pkt.Data().ExtractVV())

	copy(buf[4:], vv.ToView())

	e.Writer.Write(buf, offset)
}
