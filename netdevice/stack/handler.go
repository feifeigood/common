package stack

// for attached https://github.com/Dreamacro/clash/blob/master/tunnel/tunnel.go

type Handler interface {
	Add(TCPConn)
	AddPacket(UDPPacket)
}
