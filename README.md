# go-mockdns

[![Reference](https://godoc.org/github.com/foxcpp/go-mockdns?status.svg)](https://godoc.org/github.com/foxcpp/go-mockdns)

Boilerplate for testing of code involving DNS lookups, including ~~unholy~~
hacks to redirect `net.Lookup*` calls.

## Example

Trivial mock resolver, for cases where tested code supports custom resolvers:
```go
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
```

~~Unholy~~ hack for cases where it doesn't:
```go
srv, _ := mockdns.NewServer(map[string]mockdns.Zone{
    "example.org.": {
        A: []string{"1.2.3.4"},
    },
}, false)
defer srv.Close()

srv.PatchNet(net.DefaultResolver)
defer mockdns.UnpatchNet(net.DefaultResolver)

addrs, err := net.LookupHost("example.org")
fmt.Println(addrs, err)

// Output:
// [1.2.3.4] <nil>
```

Note, if you need to replace net.Dial calls and tested code supports custom
net.Dial, patch the resolver object inside it instead of net.DefaultResolver.
If tested code supports Dialer-like objects - use Resolver itself, it
implements Dial and DialContext methods.

### Complete Example for Unit Tests

Imagine some business code which involves DNS lookups:

```go
package domain

import "net"

func QueryTxtRecord(fqdn string) ([]string, error) {
	txtRecords, err := net.LookupTXT(fqdn)
    // Do some other stuff here...	
    return txtRecords, err
}
```

Setup mocked DNS in your tests:

```go
package domain

import (
	"github.com/foxcpp/go-mockdns"
	"github.com/stretchr/testify/assert"
	"log"
	"net"
	"testing"
)

func TestQueryTxtRecord(t *testing.T) {
	srv, err := mockdns.NewServer(map[string]mockdns.Zone{
		"foo.example.com.": { // Dot at the end is mandatory.
			TXT: []string{"Hello, world!"},
		},
	}, false)
	defer srv.Close()
	
	if err != nil {
		log.Fatalln(err)
	}

	srv.PatchNet(net.DefaultResolver)
	defer mockdns.UnpatchNet(net.DefaultResolver)

	txtRecords, err = QueryTxtRecord("foo.example.com")

	// Assert here.
}
```
