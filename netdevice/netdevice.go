package netdevice

import "gvisor.dev/gvisor/pkg/tcpip/stack"

type Device interface {
	stack.LinkEndpoint
	Close() error
	Name() string
	Type() string
}
