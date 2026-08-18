package roothints

import "testing"

// Root hints are read from a file at startup, and a truncated or mangled one
// must fail rather than take the daemon down or, worse, yield a hint list that
// looks usable and points nowhere.
func FuzzParse(f *testing.F) {
	f.Add(".                        3600000  NS    A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET.      3600000  A     198.41.0.4\n")
	f.Add(".  NS  a.\na.  AAAA  2001:503:ba3e::2:30\n")
	f.Add("")
	f.Add("garbage")

	f.Fuzz(func(t *testing.T, zone string) {
		servers, err := Parse(zone)
		if err != nil {
			return
		}
		for _, s := range servers {
			if s.Name == "" {
				t.Fatal("accepted a root server with no name")
			}
			for _, a := range s.Addrs {
				if !a.IsValid() {
					t.Fatalf("accepted an invalid address for %s", s.Name)
				}
			}
		}
	})
}
