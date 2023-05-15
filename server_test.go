package mockdns

import (
	"context"
	"fmt"
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
	srv.Resolver().SetSkipCNAME(true)
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

func TestServer_AddZone_Simple(t *testing.T) {
	const (
		initialZoneName    = "initial.example."
		additionalZoneName = "additional.example."
		expectedName       = "resolved.example"
	)

	// create server with initial zone record
	srv, err := NewServer(map[string]Zone{
		initialZoneName: Zone{
			CNAME: expectedName,
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// ensure initial zone record resolves correctly
	resolvedInitialName, err := srv.Resolver().LookupCNAME(context.Background(), initialZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if expectedName != resolvedInitialName {
		t.Fatalf("expected: %s; got: %s", expectedName, resolvedInitialName)
	}

	// add additional zone record
	err = srv.AddZone(additionalZoneName, Zone{
		CNAME: expectedName,
	})
	if err != nil {
		t.Fatal(err)
	}

	// ensure additional zone record resolves correctly
	resolvedAdditionalName, err := srv.Resolver().LookupCNAME(context.Background(), additionalZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if expectedName != resolvedAdditionalName {
		t.Fatalf("expected: %s; got: %s", expectedName, resolvedInitialName)
	}
}

func TestServer_AddZone_Existing(t *testing.T) {
	const (
		initialZoneName = "initial.example."
		expectedName    = "expected.example"
		unexpectedName  = "unexpected.example"
	)

	var expectedErr = fmt.Errorf(ErrExistingZoneFmt, initialZoneName)

	// create server with initial zone record
	srv, err := NewServer(map[string]Zone{
		initialZoneName: Zone{
			CNAME: expectedName,
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// ensure initial zone record resolves correctly
	resolvedInitialName, err := srv.Resolver().LookupCNAME(context.Background(), initialZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if expectedName != resolvedInitialName {
		t.Fatalf("expected: %q but got: %q", initialZoneName, resolvedInitialName)
	}

	// attempt to add existing zone record
	err = srv.AddZone(initialZoneName, Zone{
		CNAME: unexpectedName,
	})
	if expectedErr.Error() != err.Error() {
		t.Fatalf("expected error %q but got %q", expectedErr, err)
	}

	// ensure initial zone record resolves correctly
	resolvedInitialName, err = srv.Resolver().LookupCNAME(context.Background(), initialZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if expectedName != resolvedInitialName {
		t.Fatalf("expected: %q but got: %q", initialZoneName, resolvedInitialName)
	}

	// ensure unexpected zone record does not resolve
	_, err = srv.Resolver().LookupCNAME(context.Background(), unexpectedName)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestServer_AddZone_Concurrent(t *testing.T) {
	const (
		initialZoneName    = "initial.example."
		additionalZoneName = "additional.example."
		expectedName       = "resolved.example"
	)

	var (
		errCh = make(chan error, 1)
	)

	// create server with initial zone record
	srv, err := NewServer(map[string]Zone{
		initialZoneName: Zone{
			CNAME: expectedName,
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	go func() {
		// add additional zone record
		err := srv.AddZone(additionalZoneName, Zone{
			CNAME: expectedName,
		})
		if err != nil {
			errCh <- err
		}

		// ensure additional zone record resolves correctly
		resolvedAdditionalName, err := srv.Resolver().LookupCNAME(context.Background(), additionalZoneName)
		if err != nil {
			errCh <- err
		}
		if expectedName != resolvedAdditionalName {
			errCh <- fmt.Errorf("expected: %s but got: %s", expectedName, resolvedAdditionalName)
		}

		close(errCh)
	}()

	// ensure initial zone record resolves correctly
	resolvedInitialName, err := srv.Resolver().LookupCNAME(context.Background(), initialZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if expectedName != resolvedInitialName {
		t.Fatalf("expected: %s; got: %s", expectedName, resolvedInitialName)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
