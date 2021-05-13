package core

import (
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Stack go netstack provided by gvisor.dev
type Stack struct {
	Device  Device
	Handler Handler
	Stack   *stack.Stack
}

func (s *Stack) Start(device Device, handler Handler) (err error) {
	s.Device = device
	s.Handler = handler

	// init netstack by gvisor.dev
	s.Stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	defer func(s *stack.Stack) {
		if err != nil {
			s.Close()
		}
	}(s.Stack)

	// set NICID to 1
	const NICID = tcpip.NICID(1)

	// WithDefaultTTL sets the default TTL used by stack.
	{
		opt := tcpip.DefaultTTLOption(64)
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set ipv4 default TTL: %s", tcperr)
			return
		}
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set ipv6 default TTL: %s", tcperr)
			return
		}
	}

	// set forwarding
	if tcperr := s.Stack.SetForwarding(ipv4.ProtocolNumber, true); tcperr != nil {
		err = fmt.Errorf("set ipv4 forwarding error: %s", tcperr)
		return
	}
	if tcperr := s.Stack.SetForwarding(ipv6.ProtocolNumber, true); tcperr != nil {
		err = fmt.Errorf("set ipv6 forwarding error: %s", tcperr)
		return
	}

	// WithICMPBurst sets the number of ICMP messages that can be sent
	// in a single burst.
	s.Stack.SetICMPBurst(50)

	// WithICMPLimit sets the maximum number of ICMP messages permitted
	// by rate limiter.
	s.Stack.SetICMPLimit(rate.Limit(1000))

	// WithTCPBufferSizeRange sets the receive and send buffer size range for TCP.
	{
		rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt); tcperr != nil {
			err = fmt.Errorf("set TCP receive buffer size range: %s", tcperr)
			return
		}
		sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt); tcperr != nil {
			err = fmt.Errorf("set TCP send buffer size range: %s", tcperr)
			return
		}
	}

	// WithTCPCongestionControl sets the current congestion control algorithm.
	{
		opt := tcpip.CongestionControlOption("reno")
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP congestion control algorithm: %s", tcperr)
			return
		}
	}

	// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
	{
		opt := tcpip.TCPDelayEnabled(false)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP delay: %s", err)
			return
		}
	}

	// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP moderate receive buffer: %s", tcperr)
			return
		}
	}

	// WithTCPSACKEnabled sets the SACK option for TCP.
	{
		opt := tcpip.TCPSACKEnabled(true)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP SACK: %s", tcperr)
			return
		}
	}

	mustSubnet := func(s string) tcpip.Subnet {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Errorf("unable to ParseCIDR(%s): %w", s, err))
		}

		subnet, err := tcpip.NewSubnet(tcpip.Address(ipnet.IP), tcpip.AddressMask(ipnet.Mask))
		if err != nil {
			panic(fmt.Errorf("unable to NewSubnet(%s): %w", ipnet, err))
		}
		return subnet
	}

	// Add default route table for IPv4 and IPv6
	// This will handle all incoming ICMP packets.
	s.Stack.SetRouteTable([]tcpip.Route{
		{
			// Destination: header.IPv4EmptySubnet,
			Destination: mustSubnet("0.0.0.0/0"),
			NIC:         NICID,
		},
		{
			// Destination: header.IPv6EmptySubnet,
			Destination: mustSubnet("::/0"),
			NIC:         NICID,
		},
	})

	// Important: We must initiate transport protocol handlers
	// before creating NIC, otherwise NIC would dispatch packets
	// to stack and cause race condition.
	s.Stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s.Stack, 16<<10, 1<<15, s.HandleStream).HandlePacket)
	s.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, s.HandlePacket)

	// WithCreatingNIC creates NIC for stack.
	if tcperr := s.Stack.CreateNIC(NICID, CreateEndpoint(device)); tcperr != nil {
		err = fmt.Errorf("fail to create NIC in stack: %s", tcperr)
		return
	}

	// WithPromiscuousMode sets promiscuous mode in the given NIC.
	// In past we did s.AddAddressRange to assign 0.0.0.0/0 onto
	// the interface. We need that to be able to terminate all the
	// incoming connections - to any ip. AddressRange API has been
	// removed and the suggested workaround is to use Promiscuous
	// mode. https://github.com/google/gvisor/issues/3876
	//
	// Ref: https://github.com/majek/slirpnetstack/blob/master/stack.go
	if tcperr := s.Stack.SetPromiscuousMode(NICID, true); tcperr != nil {
		err = fmt.Errorf("set promiscuous mode: %s", tcperr)
		return
	}

	// WithSpoofing sets address spoofing in the given NIC, allowing
	// endpoints to bind to any address in the NIC.
	// Enable spoofing if a stack may send packets from unowned addresses.
	// This change required changes to some netgophers since previously,
	// promiscuous mode was enough to let the netstack respond to all
	// incoming packets regardless of the packet's destination address. Now
	// that a stack.Route is not held for each incoming packet, finding a route
	// may fail with local addresses we don't own but accepted packets for
	// while in promiscuous mode. Since we also want to be able to send from
	// any address (in response the received promiscuous mode packets), we need
	// to enable spoofing.
	//
	// Ref: https://github.com/google/gvisor/commit/8c0701462a84ff77e602f1626aec49479c308127
	if tcperr := s.Stack.SetSpoofing(NICID, true); tcperr != nil {
		err = fmt.Errorf("set spoofing: %s", tcperr)
		return
	}

	return
}

// HandleStream is to handle incoming TCP connections
func (s *Stack) HandleStream(r *tcp.ForwarderRequest) {
	id := r.ID()
	wq := waiter.Queue{}
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		log.Printf("tcp %v:%v <---> %v:%v create endpoint error: %v\n",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			tcperr,
		)
		// prevent potential half-open TCP connection leak.
		r.Complete(true)
		return
	}
	r.Complete(false)

	// set keepalive
	if err := func(ep tcpip.Endpoint) error {
		ep.SocketOptions().SetKeepAlive(true)
		idleOpt := tcpip.KeepaliveIdleOption(60 * time.Second)
		if tcperr := ep.SetSockOpt(&idleOpt); tcperr != nil {
			return fmt.Errorf("set keepalive idle: %s", tcperr)
		}
		intervalOpt := tcpip.KeepaliveIntervalOption(30 * time.Second)
		if tcperr := ep.SetSockOpt(&intervalOpt); tcperr != nil {
			return fmt.Errorf("set keepalive interval: %s", tcperr)
		}
		return nil
	}(ep); err != nil {
		log.Printf("tcp %v:%v <---> %v:%v create endpoint error: %v\n", net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			err)
	}

	go s.Handler.Handle((*TCPConn)(unsafe.Pointer(gonet.NewTCPConn(&wq, ep))))
}

func (s *Stack) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
	udpHdr := header.UDP(pkt.TransportHeader().View())
	if int(udpHdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		log.Printf("udp %v:%v <---> %v:%v malformed packet\n",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		)
		s.Stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	if !verifyChecksum(udpHdr, pkt) {
		log.Printf("udp %v:%v <---> %v:%v checksum error\n",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		)
		s.Stack.Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	s.Stack.Stats().UDP.PacketsReceived.Increment()

	go s.Handler.HandlePacket(&UDPPacket{
		stack: s,
		data:  pkt.Data().ExtractVV(),
		routeInfo: struct {
			src tcpip.Address
			nic tcpip.NICID
			pn  tcpip.NetworkProtocolNumber
			id  stack.TransportEndpointID
		}{
			src: pkt.Network().SourceAddress(),
			nic: pkt.NICID,
			pn:  pkt.NetworkProtocolNumber,
			id:  id,
		},
	})
	return true
}

// Close is to close the stack
func (s *Stack) Close() error {
	s.Stack.Close()
	return nil
}

// use unsafe package
var _ unsafe.Pointer = unsafe.Pointer(nil)

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
//
//go:linkname sendUDP gvisor.dev/gvisor/pkg/tcpip/transport/udp.sendUDP
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) *tcpip.Error

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
// On IPv4, UDP checksum is optional, and a zero value means the transmitter
// omitted the checksum generation (RFC768).
// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
//
//go:linkname verifyChecksum gvisor.dev/gvisor/pkg/tcpip/transport/udp.verifyChecksum
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool
