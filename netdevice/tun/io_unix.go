// +build darwin freebsd openbsd

package tun

import "github.com/feifeigood/common/bytes/pool"

const (
	offset     = 4
	defaultMTU = 1500
)

func (t *TUN) Read(packet []byte) (n int, err error) {
	buf := pool.Get(offset + len(packet))
	defer pool.Put(buf)

	if n, err = t.nt.Read(buf, offset); err != nil {
		return
	}

	copy(packet, buf[offset:offset+n])
	return
}

func (t *TUN) Write(packet []byte) (int, error) {
	buf := pool.Get(offset + len(packet))
	defer pool.Put(buf)

	copy(buf[offset:], packet)
	return t.nt.Write(buf[:offset+len(packet)], offset)
}
