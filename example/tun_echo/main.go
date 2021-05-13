package main

import (
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/feifeigood/common/lg"
	"github.com/feifeigood/common/netstack"
	"github.com/feifeigood/common/tuntap"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

var (
	// ipstack *stack.Stack
	ipstack *netstack.Stack
	logger  *log.Logger
)

func init() {
	logger = log.New(os.Stderr, "[tun_echo] ", log.Ldate|log.Ltime|log.Lmicroseconds)
}

func logf(lvl lg.LogLevel, s string, args ...interface{}) {
	lg.Logf(logger, lg.DEBUG, lg.INFO, s, args...)
}

func echo(c *gonet.TCPConn) {
	defer c.Close()
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			logf(lg.ERROR, "read err - %s", err)
			break
		}
		c.Write(buf[:n])
	}
	logf(lg.INFO, "connection closed")
}

type fakeHandler struct{}

func (h *fakeHandler) Handle(conn netstack.Conn, addr net.Addr) error {
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			logf(lg.ERROR, "read err - %s", err)
			break
		}
		conn.Write(buf[:n])
	}
	logf(lg.INFO, "connection closed")

	return nil
}

func (h *fakeHandler) HandlePacket(netstack.Packet, net.Addr) error {
	return errors.New("no implemented")
}

func main() {
	name := "utun"

	rand.Seed(time.Now().UnixNano())

	ifce, err := tuntap.NewTun(name)
	if err != nil {
		lg.LogFatal("[tun_echo] ", "%s", err)
	}

	if err := ifce.SetInterfaceAddress("198.18.0.1/24"); err != nil {
		lg.LogFatal("[tun_echo] ", "%s", err)
	}

	ipstack = netstack.NewStack(&fakeHandler{})
	if err := ipstack.Start(ifce); err != nil {
		lg.LogFatal("[tun_echo] ", "%s", err)
	}

	exit := make(chan os.Signal, 1)
	logf(lg.INFO, "waiting....")
	<-exit
	os.Exit(0)
}
