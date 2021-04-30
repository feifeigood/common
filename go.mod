module github.com/feifeigood/common

go 1.16

require (
	github.com/stretchr/testify v1.7.0
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.zx2c4.com/wireguard v0.0.0-20210427022245-097af6e1351b
	gvisor.dev/gvisor v0.0.0-20210429234245-c958c5a4f103
)

replace gvisor.dev/gvisor => github.com/xjasonlyu/gvisor v0.0.0-20210321122453-eb40de9b30e3
