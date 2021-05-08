package tuntap

import "errors"

var (
	ErrNotReady    = errors.New("device is not ready")
	ErrClosed      = errors.New("device was closed")
	ErrUnsupported = errors.New("device is unsupported on this platform")
)

// Interface represents a TUN/TAP network interface
type Interface interface {
	// return name of TUN/TAP interface
	Name() string

	// implement io.Reader interface, read bytes into p from TUN/TAP interface
	Read(p []byte) (n int, err error)

	// implement io.Writer interface, write bytes from p to TUN/TAP interface
	Write(p []byte) (n int, err error)

	// implement io.Closer interface, must be called done with TUN/TAP interface
	Close() error

	// return string representation of TUN/TAP interface
	String() string
}

func Tun(name string) (Interface, error) {
	return newTUN(name)
}

func Tap(name string) (Interface, error) {
	return newTAP(name)
}
