// +build !linux,!darwin,!windows

package tuntap

func newTUN(name string) (Interface, error) {
	return nil, ErrUnsupported
}

func newTAP(name string) (Interface, error) {
	return nil, ErrUnsupported
}
