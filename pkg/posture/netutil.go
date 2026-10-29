package posture

import (
	"net"
	"strconv"
)

func itoaStd(i int) string { return strconv.Itoa(i) }

func net_join(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
