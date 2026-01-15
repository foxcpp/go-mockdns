package mockdns

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServer_PatchNet(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"example.org.": {
			A:    []string{"1.2.3.4"},
			AAAA: []string{"::1"},
		},
		"example.net.": {},
		"aaa.example.org.": {
			CNAME: "example.org.",
		},
	}, false)
	assertNoError(t, err)
	defer srv.Close()

	r := srv.NewResolver()

	// Existing zone with A and AAAA.
	addrs, err := r.LookupHost(context.Background(), "example.org")
	assertNoError(t, err)

	sort.Strings(addrs)
	want := []string{"1.2.3.4", "::1"}
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("Wrong result, want %v, got %v", want, addrs)
	}

	// Existing zone without A or AAAA.
	addrs, err = r.LookupHost(context.Background(), "example.net")
	assertNotFoundError(t, err)

	// Non-existing zone.
	_, err = r.LookupHost(context.Background(), "example.com")
	assertNotFoundError(t, err)

	// Existing zone CNAME pointing to a zone with with A and AAAA.
	addrs, err = r.LookupHost(context.Background(), "aaa.example.org")
	assertNoError(t, err)
	sort.Strings(addrs)
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("Wrong result, want %v, got %v", want, addrs)
	}
}

func TestServer_PatchNet_LookupMX(t *testing.T) {
	srv, err := NewServer(map[string]Zone{
		"example.org.": {
			MX: []net.MX{{Host: "mx.example.org.", Pref: 10}},
		},
	}, false)
	assertNoError(t, err)
	defer srv.Close()

	r := srv.NewResolver()

	mxs, err := r.LookupMX(context.Background(), "example.org")
	assertNoError(t, err)
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
			TXT: []string{"something", "else"},
			MX: []net.MX{
				{Host: "mxa.mailgun.ort.", Pref: 10},
				{Host: "mxb.mailgun.org.", Pref: 10},
			},
		},
	}, false)
	assertNoError(t, err)
	defer srv.Close()

	r := srv.NewResolver()

	// LookupCNAME does not follow the CNAME chain and returns the first CNAME.
	hostname, err := r.LookupCNAME(context.Background(), "foo.io")
	assertNoError(t, err)
	if hostname != "bar.io." {
		t.Errorf("Wrong CNAME, want %q, got %q", "bar.io.", hostname)
	}

	// Any other Lookup* method including LookupHost follows the CNAME chain.
	addrs, err := r.LookupTXT(context.Background(), "foo.io")
	assertNoError(t, err)
	sort.Strings(addrs)
	want := []string{"else", "something"}
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
		"example.org.": {
			Misc: map[dns.Type][]dns.RR{
				dns.Type(dns.TypeTLSA): {
					rec,
				},
			},
		},
	}, false)
	assertNoError(t, err)
	defer srv.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeTLSA)
	msg.SetEdns0(4096, false)
	msg.AuthenticatedData = true
	cl := dns.Client{}
	reply, _, err := cl.Exchange(msg, srv.LocalAddr().String())
	assertNoError(t, err)
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
	assertNoError(t, err)

	// FIXME(maxim): I do not understand why SkipCNAME is needed at all in
	//  resolver. DNS behavior is to follow CNAMEs unless queried for a CNAME,
	//  Therefore there is no need for SkipCNAME in server tests.
	//srv.Resolver().SkipCNAME = true
	defer srv.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("www.example.org.", dns.TypeNS)
	cl := dns.Client{}
	reply, _, err := cl.Exchange(msg, srv.LocalAddr().String())
	assertNoError(t, err)
	if len(reply.Answer) != 1 {
		t.Fatal("Wrong amount of records in response:", len(reply.Answer))
	}
	if !reply.MsgHdr.Authoritative {
		t.Fatal("The authoritative flag should be set")
	}
}

func TestServer_MutateRR(t *testing.T) {
	srv, err := NewServer(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	r := srv.NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("A/AAAA", func(t *testing.T) {
		lookupName := "foo.io"

		_, err = r.LookupHost(ctx, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR(lookupName, RRTypeA, "192.168.2.19")
		assertNoError(t, err)
		got, err := r.LookupHost(ctx, lookupName)
		assertNoError(t, err)
		want := []string{"192.168.2.19"}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeAAAA, "2001:db8:130f::9c0:876a:130b")
		assertNoError(t, err)
		got, err = r.LookupHost(ctx, lookupName)
		assertNoError(t, err)
		want = []string{"192.168.2.19", "2001:db8:130f::9c0:876a:130b"}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeAAAA, "::FFFF:81.19.128.3")
		assertNoError(t, err)
		got, err = r.LookupHost(ctx, lookupName)
		assertNoError(t, err)
		sort.Sort(sort.StringSlice(got))
		want = []string{"192.168.2.19", "2001:db8:130f::9c0:876a:130b", "81.19.128.3"}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupHost(ctx, lookupName)
		assertNotFoundError(t, err)
	})

	t.Run("CNAME", func(t *testing.T) {
		lookupName := "foo.io"

		_, err = r.LookupCNAME(ctx, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR(lookupName, RRTypeCNAME, "bar.io.")
		assertNoError(t, err)
		got, err := r.LookupCNAME(ctx, lookupName)
		assertNoError(t, err)
		want := "bar.io."
		if want != got {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeCNAME, "zoom.io.")
		assertNoError(t, err)
		got, err = r.LookupCNAME(ctx, lookupName)
		assertNoError(t, err)
		want = "zoom.io."
		if want != got {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupCNAME(ctx, lookupName)
		assertNotFoundError(t, err)
	})

	t.Run("MX", func(t *testing.T) {
		lookupName := "foo.io"

		_, err = r.LookupMX(ctx, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR(lookupName, RRTypeMX, "19 bar.io.")
		assertNoError(t, err)
		got, err := r.LookupMX(ctx, lookupName)
		assertNoError(t, err)
		want := []*net.MX{{Host: "bar.io.", Pref: 19}}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeMX, "23 zoom.io.")
		assertNoError(t, err)
		got, err = r.LookupMX(ctx, lookupName)
		assertNoError(t, err)
		want = []*net.MX{
			{Host: "bar.io.", Pref: 19},
			{Host: "zoom.io.", Pref: 23},
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupMX(ctx, lookupName)
		assertNotFoundError(t, err)
	})

	t.Run("NS", func(t *testing.T) {
		lookupName := "foo.io"

		_, err = r.LookupNS(ctx, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR(lookupName, RRTypeNS, "bar.io.")
		assertNoError(t, err)
		got, err := r.LookupNS(ctx, lookupName)
		assertNoError(t, err)
		want := []*net.NS{{"bar.io."}}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeNS, "zoom.io.")
		assertNoError(t, err)
		got, err = r.LookupNS(ctx, lookupName)
		assertNoError(t, err)
		want = []*net.NS{{"bar.io."}, {"zoom.io."}}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupNS(ctx, lookupName)
		assertNotFoundError(t, err)
	})

	t.Run("PTR", func(t *testing.T) {
		lookupAddr := "192.168.2.19"

		_, err = r.LookupAddr(ctx, lookupAddr)
		assertNotFoundError(t, err)

		err = srv.AppendRR("19.2.168.192.in-addr.arpa.", RRTypePTR, "bar.io.")
		assertNoError(t, err)
		got, err := r.LookupAddr(ctx, lookupAddr)
		assertNoError(t, err)
		want := []string{"bar.io."}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR("19.2.168.192.in-addr.arpa.", RRTypePTR, "zoom.io.")
		assertNoError(t, err)
		got, err = r.LookupAddr(ctx, lookupAddr)
		assertNoError(t, err)
		want = []string{"bar.io.", "zoom.io."}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupAddr(ctx, lookupAddr)
		assertNotFoundError(t, err)
	})

	t.Run("SRV", func(t *testing.T) {
		lookupService := "http"
		lookupProto := "tcp"
		lookupName := "foo.io"

		_, _, err := r.LookupSRV(ctx, lookupService, lookupProto, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR("_http._tcp.foo.io.", RRTypeSRV, "23 10 8080 bar.io.")
		assertNoError(t, err)
		gotName, gotRRs, err := r.LookupSRV(ctx, lookupService, lookupProto, lookupName)
		assertNoError(t, err)
		wantName := "_http._tcp.foo.io."
		if !reflect.DeepEqual(wantName, gotName) {
			t.Fatalf("Wrong result: want=%v, got=%v", wantName, gotName)
		}
		wantRRs := []*net.SRV{{Target: "bar.io.", Port: 8080, Priority: 23, Weight: 10}}
		if !reflect.DeepEqual(wantRRs, gotRRs) {
			t.Fatalf("Wrong result: want=%v, got=%v", wantRRs, gotRRs)
		}

		err = srv.AppendRR("_http._tcp.foo.io.", RRTypeSRV, "19 10 8081 zoom.io.")
		assertNoError(t, err)
		gotName, gotRRs, err = r.LookupSRV(ctx, lookupService, lookupProto, lookupName)
		assertNoError(t, err)
		if !reflect.DeepEqual(wantName, gotName) {
			t.Fatalf("Wrong result: want=%v, got=%v", wantName, gotName)
		}
		wantRRs = []*net.SRV{
			{Target: "zoom.io.", Port: 8081, Priority: 19, Weight: 10},
			{Target: "bar.io.", Port: 8080, Priority: 23, Weight: 10},
		}
		if !reflect.DeepEqual(wantRRs, gotRRs) {
			t.Fatalf("Wrong result: want=%v, got=%v", wantRRs, gotRRs)
		}

		srv.Reset()
		_, _, err = r.LookupSRV(ctx, lookupService, lookupProto, lookupName)
		assertNotFoundError(t, err)
	})

	t.Run("TXT", func(t *testing.T) {
		lookupName := "foo.io"

		_, err = r.LookupTXT(ctx, lookupName)
		assertNotFoundError(t, err)

		err = srv.AppendRR(lookupName, RRTypeTXT, "v=spf1 -all")
		assertNoError(t, err)
		got, err := r.LookupTXT(ctx, lookupName)
		assertNoError(t, err)
		want := []string{"v=spf1 -all"}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		err = srv.AppendRR(lookupName, RRTypeTXT, "v=dkim1; k=rsa; p=kaboom")
		assertNoError(t, err)
		got, err = r.LookupTXT(ctx, lookupName)
		assertNoError(t, err)
		want = []string{"v=spf1 -all", "v=dkim1; k=rsa; p=kaboom"}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("Wrong result: want=%v, got=%v", want, got)
		}

		srv.Reset()
		_, err = r.LookupTXT(ctx, lookupName)
		assertNotFoundError(t, err)
	})
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}
