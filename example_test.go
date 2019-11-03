package mockdns_test

import (
	"context"
	"fmt"
	"net"

	"github.com/foxcpp/go-mockdns"
)

func ExampleResolver() {
	// Use for code that supports custom resolver implementations.
	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"example.org.": {
				A: []string{"1.2.3.4"},
			},
		},
	}

	addrs, err := r.LookupHost(context.Background(), "example.org")
	fmt.Println(addrs, err)

	// Output:
	// [1.2.3.4] <nil>
}

func ExampleServer_PatchNet() {
	// Use for code that directly calls net.Lookup*.
	srv, _ := mockdns.NewServer(map[string]mockdns.Zone{
		"example.org.": {
			A: []string{"1.2.3.4"},
		},
	})
	defer srv.Close()

	srv.PatchNet(net.DefaultResolver)
	// Important if net.DefaultResolver is modified.
	defer mockdns.UnpatchNet(net.DefaultResolver)

	addrs, err := net.LookupHost("example.org")
	fmt.Println(addrs, err)

	// Output:
	// [1.2.3.4] <nil>
}
