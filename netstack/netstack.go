package netstack

import (
	"io"
	"log"

	"github.com/feifeigood/common/netstack/core"
)

type Device interface {
	io.Closer
	core.Device
}

type Stack struct {
	core.Stack
	Handler Handler
}

func NewStack(handler Handler) *Stack {
	return &Stack{Handler: handler}
}

func (s *Stack) Start(device Device) error {
	return s.Stack.Start(device, s)
}

func (s *Stack) Handle(conn *core.TCPConn) {
	if err := s.Handler.Handle(conn, conn.LocalAddr()); err != nil {
		log.Printf("netstack handle tcp conn error - %v\n", err)
	}
}

func (s *Stack) HandlePacket(pkt *core.UDPPacket) {
	if err := s.Handler.HandlePacket(pkt, pkt.LocalAddr()); err != nil {
		log.Printf("netstack handle udp packet error - %v\n", err)
	}
}
