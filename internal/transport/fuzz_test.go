package transport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/miekg/dns"
)

func seedWire(f *testing.F) {
	f.Helper()
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.SetEdns0(1232, true)
	raw, err := m.Pack()
	if err != nil {
		f.Fatalf("packing a seed: %v", err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01})
	// A compression pointer that refers to itself.
	f.Add([]byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01})
}

// Everything on the wire is attacker-controlled. The acceptance path decides
// whether a packet becomes work, and it must never panic and never answer
// something it could not parse — replying to garbage from a spoofed source is
// what turns a resolver into a reflector.
func FuzzQueryAcceptance(f *testing.F) {
	seedWire(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil {
			return
		}
		// These are the same conditions every listener applies before a query
		// reaches the resolver.
		if req.Response || len(req.Question) != 1 {
			return
		}

		// Anything we would answer has to produce a reply that packs, or the
		// listener would have a message it cannot send and no way to say so.
		for _, rcode := range []int{dns.RcodeRefused, dns.RcodeServerFailure} {
			resp := errorResponse(req, rcode)
			if resp == nil {
				t.Fatal("errorResponse returned nil for a query we accepted")
			}
			if resp.Id != req.Id {
				t.Fatalf("reply id %d does not match request id %d", resp.Id, req.Id)
			}
			if !resp.Response {
				t.Fatal("reply is not marked as a response")
			}
			if _, err := resp.Pack(); err != nil {
				t.Fatalf("a reply we would have sent does not pack: %v", err)
			}
		}
	})
}

// The DoH query parameter is base64 supplied by anyone who can reach the
// endpoint, decoded before any DNS parsing happens.
func FuzzDoHReadQuery(f *testing.F) {
	f.Add("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
	f.Add("")
	f.Add("!!!!")
	f.Add("QUJD")

	d := &DoH{}
	f.Fuzz(func(t *testing.T, q string) {
		r := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
		r.URL.RawQuery = url.Values{"dns": {q}}.Encode()
		raw, err := d.readQuery(r)
		if err != nil {
			return
		}
		if len(raw) > maxDoHBody {
			t.Fatalf("accepted a %d byte body, over the %d cap", len(raw), maxDoHBody)
		}
	})
}

// The POST form carries the message as a body, with the size cap being the only
// thing between a caller and unbounded memory.
func FuzzDoHReadBody(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 4096))

	d := &DoH{}
	f.Fuzz(func(t *testing.T, body []byte) {
		r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/dns-message")
		raw, err := d.readQuery(r)
		if err != nil {
			return
		}
		if len(raw) > maxDoHBody {
			t.Fatalf("accepted a %d byte body, over the %d cap", len(raw), maxDoHBody)
		}
	})
}
