// +build darwin

package tuntap

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (a *Tun) setInterfaceAddress4(addr, mask, gw string) error {

	output, err := exec.Command("ifconfig", strings.Split(fmt.Sprintf("%s inet %s netmask %s %s", a.Name, addr, mask, gw), " ")...).Output()
	if err != nil {
		if len(output) != 0 {
			return fmt.Errorf("%v, output: %s", err, output)
		}
		return err
	}

	a.Gateway4 = parse4(gw)

	return nil
}

func (a *Tun) setInterfaceAddress6(addr, mask, gw string) error {

	output, err := exec.Command("ifconfig", strings.Split(fmt.Sprintf("%s inet6 %s netmask %s %s", a.Name, addr, mask, gw), " ")...).Output()
	if err != nil {
		if len(output) != 0 {
			return fmt.Errorf("%v, output: %s", err, output)
		}
		return err
	}

	a.Gateway6 = parse6(gw)

	return nil
}

func roundup(a uintptr) uintptr {
	if a > 0 {
		return 1 + ((a - 1) | (unsafe.Sizeof(uint32(0)) - 1))
	}

	return unsafe.Sizeof(uint32(0))
}

func (a *Tun) addRouteEntry4(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer func() {
		unix.Shutdown(fd, unix.SHUT_RDWR)
		unix.Close(fd)
	}()

	l := roundup(unix.SizeofSockaddrInet4)

	type rt_message struct {
		hdr unix.RtMsghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(a.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(unix.RtMsghdr{})+l+l+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.Msglen = uint16(unsafe.Sizeof(unix.RtMsghdr{}) + l + l + l)
	msg.hdr.Version = unix.RTM_VERSION
	msg.hdr.Type = unix.RTM_ADD
	msg.hdr.Index = uint16(interf.Index)
	msg.hdr.Flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.Addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.Pid = 0
	msg.hdr.Seq = 0
	msg.hdr.Errno = 0
	msg.hdr.Use = 0
	msg.hdr.Inits = 0

	msg_dest := (*unix.RawSockaddrInet4)(unsafe.Pointer(&msg.bb))
	msg_dest.Len = unix.SizeofSockaddrInet4
	msg_dest.Family = unix.AF_INET

	msg_gateway := (*unix.RawSockaddrInet4)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l))
	msg_gateway.Len = unix.SizeofSockaddrInet4
	msg_gateway.Family = unix.AF_INET
	msg_gateway.Addr = a.Gateway4

	msg_mask := (*unix.RawSockaddrInet4)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l + l))
	msg_mask.Len = unix.SizeofSockaddrInet4
	msg_mask.Family = unix.AF_INET

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ipv4 := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()

		msg_dest.Addr = *(*[4]byte)(unsafe.Pointer(&ipv4[0]))
		msg_mask.Addr = *(*[4]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.Msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.Seq++
	}

	return nil
}

func (a *Tun) addRouteEntry6(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer func() {
		unix.Shutdown(fd, unix.SHUT_RDWR)
		unix.Close(fd)
	}()

	l := roundup(unix.SizeofSockaddrInet6)

	type rt_message struct {
		hdr unix.RtMsghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(a.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(unix.RtMsghdr{})+l+l+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.Msglen = uint16(unsafe.Sizeof(unix.RtMsghdr{}) + l + l + l)
	msg.hdr.Version = unix.RTM_VERSION
	msg.hdr.Type = unix.RTM_ADD
	msg.hdr.Index = uint16(interf.Index)
	msg.hdr.Flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.Addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.Pid = 0
	msg.hdr.Seq = 0
	msg.hdr.Errno = 0
	msg.hdr.Use = 0
	msg.hdr.Inits = 0

	msg_dest := (*unix.RawSockaddrInet6)(unsafe.Pointer(&msg.bb))
	msg_dest.Len = unix.SizeofSockaddrInet6
	msg_dest.Family = unix.AF_INET6

	msg_gateway := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l))
	msg_gateway.Len = unix.SizeofSockaddrInet6
	msg_gateway.Family = unix.AF_INET6
	msg_gateway.Addr = a.Gateway6

	msg_mask := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l + l))
	msg_mask.Len = unix.SizeofSockaddrInet6
	msg_mask.Family = unix.AF_INET6

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ipv6 := ipNet.IP.To16()
		mask := net.IP(ipNet.Mask).To16()

		msg_dest.Addr = *(*[16]byte)(unsafe.Pointer(&ipv6[0]))
		msg_mask.Addr = *(*[16]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.Msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.Seq++
	}

	return nil
}
