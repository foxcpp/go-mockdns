package mockdns

import (
	"net"
)

type Zone struct {
	A     []string
	AAAA  []string
	TXT   []string
	PTR   []string
	CNAME string
	MX    []net.MX
	NS    []net.NS
	SRV   []net.SRV
}
