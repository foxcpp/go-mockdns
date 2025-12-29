package mockdns

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/miekg/dns"
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
	}, false)
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
	if !isNotFound(dnsErr) {
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
	if !isNotFound(dnsErr) {
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

func TestServer_PatchNet_LookupMX(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"example.org.": Zone{
			MX: []net.MX{{Host: "mx.example.org.", Pref: 10}},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var r net.Resolver
	srv.PatchNet(&r)

	mxs, err := r.LookupMX(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(mxs, []*net.MX{{Host: "mx.example.org.", Pref: 10}}) {
		t.Fatalf("Wrong MXs")
	}
}

func TestServer_FollowCNAMEs(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"foo.io.": {
			CNAME: "bar.io.",
		},
		"bar.io.": {
			CNAME: "example.org.",
		},
		"example.org.": {
			A:    []string{"1.2.3.4"},
			AAAA: []string{"::1"},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var r net.Resolver
	srv.PatchNet(&r)

	// LookupCNAME does not follow the CNAME chain and returns the first CNAME.
	hostname, err := r.LookupCNAME(context.Background(), "foo.io")
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "bar.io." {
		t.Errorf("Wrong CNAME, want %q, got %q", "bar.io.", hostname)
	}

	// Any other Lookup* method including LookupHost follows the CNAME chain.
	addrs, err := r.LookupHost(context.Background(), "foo.io")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(addrs)
	want := []string{"1.2.3.4", "::1"}
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("Wrong result, want %v, got %v", want, addrs)
	}
}

func TestServer_LookupTLSA(t *testing.T) {
	rec := &dns.TLSA{
		Hdr: dns.RR_Header{
			Name:     "example.org.",
			Rrtype:   dns.TypeTLSA,
			Class:    dns.ClassINET,
			Ttl:      9999,
			Rdlength: 6,
		},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  "aaaaaa",
	}

	srv, err := NewServer(map[string]Zone{
		"example.org.": Zone{
			Misc: map[dns.Type][]dns.RR{
				dns.Type(dns.TypeTLSA): []dns.RR{
					rec,
				},
			},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeTLSA)
	msg.SetEdns0(4096, false)
	msg.AuthenticatedData = true
	cl := dns.Client{}
	reply, _, err := cl.Exchange(msg, srv.LocalAddr().String())
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatal("Wrong amoun of records in response:", len(reply.Answer))
	}
	if !reflect.DeepEqual(reply.Answer[0], rec) {
		t.Errorf("\nWant %#+v\n got %#+v", rec, reply.Answer[0])
	}
}

func TestServer_Authoritative(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"www.example.org.": {
			CNAME: "foo.bar.com.",
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	// FIXME(maxim): I do not understand why SkipCNAME is needed at all in
	//  resolver. DNS behavior is to follow CNAMEs unless queried for a CNAME,
	//  Therefore there is no need for SkipCNAME in server tests.
	//srv.Resolver().SkipCNAME = true
	defer srv.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("www.example.org.", dns.TypeNS)
	cl := dns.Client{}
	reply, _, err := cl.Exchange(msg, srv.LocalAddr().String())
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatal("Wrong amount of records in response:", len(reply.Answer))
	}
	if !reply.MsgHdr.Authoritative {
		t.Fatal("The authoritative flag should be set")
	}
}
