//go:build go1.18
// +build go1.18

package mockdns

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"
)

func TestResolver_LookupNetIP(t *testing.T) {
	r := &Resolver{Zones: map[string]Zone{
		"example.com.": {
			A:    []string{"192.168.0.1", "10.0.0.1"},
			AAAA: []string{"2001:db8::1", "2001:db8::2"},
		},
		"example.org.": {
			MX: []net.MX{
				{Host: "example.com.", Pref: 10},
			},
		},
	}}
	cases := []struct {
		name    string
		network string
		host    string
		want    []string
		wantErr bool
	}{
		{name: "IPv4 Only", network: "ip4", host: "example.com", want: []string{"192.168.0.1", "10.0.0.1"}, wantErr: false},
		{name: "IPv6 Only", network: "ip6", host: "example.com", want: []string{"2001:db8::1", "2001:db8::2"}, wantErr: false},
		{name: "IPv4&IPv6", network: "ip", host: "example.com", want: []string{"192.168.0.1", "10.0.0.1", "2001:db8::1", "2001:db8::2"}, wantErr: false},
		{name: "IPv4 Not Found", network: "ip4", host: "example.org", want: []string{}, wantErr: true},
		{name: "IPv6 Not Found", network: "ip6", host: "example.org", want: []string{}, wantErr: true},
		{name: "IPv4&IPv6 Not Found", network: "ip", host: "example.org", want: []string{}, wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.LookupNetIP(context.Background(), tt.network, tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("Wrong error, want %v, got %v", tt.wantErr, err)
			}
			items := make([]string, len(got))
			for i, ip := range got {
				items[i] = ip.String()
			}
			sort.Strings(items)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(items, tt.want) {
				t.Errorf("Wrong result, want %v, got %v", tt.want, items)
			}
		})

	}
}
