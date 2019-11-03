//+build start

package mockdns

import (
	"testing"
	"time"
)

func TestStart(t *testing.T) {
	srv, err := NewServer(map[string]Zone{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	time.Sleep(500 * time.Second)
}
