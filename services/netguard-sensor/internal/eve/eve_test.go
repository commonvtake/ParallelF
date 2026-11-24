package eve

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseKinds(t *testing.T) {
	cases := map[string]string{
		"flow":    `{"timestamp":"2026-11-24T12:00:00.123456+0000","event_type":"flow","in_iface":"wg-pf0","src_ip":"10.255.0.10","src_port":51000,"dest_ip":"10.255.0.1","dest_port":22,"proto":"TCP","community_id":"1:abc=","flow":{"pkts_toserver":1,"bytes_toserver":60,"state":"new","reason":"timeout"}}`,
		"dns":     `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"dns","src_ip":"10.20.1.5","dest_ip":"10.20.1.1","proto":"UDP","dns":{"type":"query","rrname":"example.org","rrtype":"A"}}`,
		"dns3":    `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"dns","src_ip":"10.20.1.5","dest_ip":"10.20.1.1","proto":"UDP","dns":{"version":3,"type":"request","queries":[{"rrname":"nested.example","rrtype":"AAAA"}]}}`,
		"http":    `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"http","src_ip":"10.20.1.5","dest_ip":"10.20.1.1","dest_port":80,"proto":"TCP","http":{"hostname":"h","url":"/pf-ng-ids-canary","http_method":"GET","status":404}}`,
		"alert":   `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"alert","src_ip":"10.20.1.5","dest_ip":"10.20.1.1","proto":"TCP","alert":{"action":"allowed","signature_id":9100001,"rev":1,"signature":"PARALLELF canary","category":"Misc activity","severity":3}}`,
		"anomaly": `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"anomaly","anomaly":{"type":"decode","event":"ipv4.trunc_pkt"}}`,
	}
	want := map[string]map[string]string{
		"flow":    {"flow.bytes_toserver": "60", "flow.state": "new"},
		"dns":     {"dns.rrname": "example.org", "dns.rrtype": "A"},
		"dns3":    {"dns.rrname": "nested.example", "dns.rrtype": "AAAA"},
		"http":    {"http.url": "/pf-ng-ids-canary", "http.status": "404"},
		"alert":   {"alert.signature_id": "9100001", "alert.severity": "3"},
		"anomaly": {"anomaly.event": "ipv4.trunc_pkt"},
	}
	for name, line := range cases {
		ev, err := Parse([]byte(line), "pfbr-1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for k, v := range want[name] {
			if ev.Details[k] != v {
				t.Errorf("%s: %s = %q, want %q", name, k, ev.Details[k], v)
			}
		}
		if len(ev.RawSHA256) != 64 {
			t.Errorf("%s: provenance hash missing", name)
		}
	}
	ev, _ := Parse([]byte(cases["flow"]), "x")
	if ev.Proto != "tcp" || ev.Interface != "wg-pf0" || ev.DstPort != 22 || !ev.Time.Equal(time.Date(2026, 11, 24, 12, 0, 0, 123456000, time.UTC)) {
		t.Fatalf("flow %+v", ev)
	}
	ev, _ = Parse([]byte(cases["dns"]), "pfbr-1")
	if ev.Interface != "pfbr-1" {
		t.Fatal("the capture interface fills a missing in_iface")
	}
}

func TestHostileInput(t *testing.T) {
	long := strings.Repeat("A", 5000)
	line := `{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"http","src_ip":"not-an-ip","src_port":99999,"proto":"TCP","http":{"url":"` + long + `","http_user_agent":"evil\u0000\u001b[31mred"}}`
	ev, err := Parse([]byte(line), "i")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Details["http.url"]) != 512 || ev.SrcIP != "" || ev.SrcPort != 0 {
		t.Fatalf("not bounded: %d %q %d", len(ev.Details["http.url"]), ev.SrcIP, ev.SrcPort)
	}
	if strings.ContainsAny(ev.Details["http.http_user_agent"], "\x00\x1b") {
		t.Fatal("control characters must be removed")
	}
	if _, err := Parse([]byte(strings.Repeat("x", 70000)), "i"); err == nil {
		t.Fatal("an oversized line must be refused")
	}
	if _, err := Parse([]byte(`{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"stats"}`), "i"); !errors.Is(err, ErrSkip) {
		t.Fatalf("stats: %v", err)
	}
	if _, err := Parse([]byte(`{"event_type":"flow","timestamp":"yesterday"}`), "i"); err == nil {
		t.Fatal("a bad timestamp must be refused")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"timestamp":"2026-11-24T12:00:00.000000+0000","event_type":"alert","alert":{"signature_id":1}}`))
	f.Add([]byte(`{"event_type":"dns","dns":{"queries":[{"rrname":1}]}}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		ev, err := Parse(line, "fuzz")
		if err != nil {
			return
		}
		for k, v := range ev.Details {
			if len(v) > 512 || len(k) > 64 {
				t.Fatalf("unbounded field %s", k)
			}
		}
	})
}
