package mockdns

import (
	"net"
)

type Zone struct {
	// Return the specified error on any lookup using this zone.
	// For Server, non-nil value results in SERVFAIL response.
	Err error

	A     []string
	AAAA  []string
	TXT   []string
	PTR   []string
	CNAME string
	MX    []net.MX
	NS    []net.NS
	SRV   []net.SRV
}
