package mockdns

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"
)

func TestServer_PatchNet(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"example.org.": Zone{
			A:    []string{"1.2.3.4"},
			AAAA: []string{"::1"},
		},
		"example.net.": Zone{},
		"aaa.example.org.": Zone{
			CNAME: "example.org.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var r net.Resolver
	srv.PatchNet(&r)

	// Existing zone with A and AAAA.
	addrs, err := r.LookupHost(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(addrs)
	want := []string{"1.2.3.4", "::1"}
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("Wrong result, want %v, got %v", want, addrs)
	}

	// Existing zone without A or AAAA.
	addrs, err = r.LookupHost(context.Background(), "example.net")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("err is not *net.DNSError, but %T", err)
	}
	if !dnsErr.IsNotFound {
		t.Fatalf("err.IsNotFound is false, should be true")
	}

	// Non-existing zone.
	_, err = r.LookupHost(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	dnsErr, ok = err.(*net.DNSError)
	if !ok {
		t.Fatalf("err is not *net.DNSError, but %T", err)
	}
	if !dnsErr.IsNotFound {
		t.Fatalf("err.IsNotFound is false, should be true")
	}

	// Existing zone CNAME pointing to a zone with with A and AAAA.
	addrs, err = r.LookupHost(context.Background(), "aaa.example.org")
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(addrs)
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("Wrong result, want %v, got %v", want, addrs)
	}
}
