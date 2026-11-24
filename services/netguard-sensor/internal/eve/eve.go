// Package eve normalizes Suricata EVE JSON records into ParallelF telemetry
// events. Every value comes from the network, so every value is treated as
// hostile: lines and fields are bounded, addresses are parsed, and only
// known fields are kept.
package eve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
)

// ErrSkip marks a valid record of a type ParallelF does not keep.
var ErrSkip = errors.New("record type not kept")

type record struct {
	Timestamp   string          `json:"timestamp"`
	EventType   string          `json:"event_type"`
	InIface     string          `json:"in_iface"`
	SrcIP       string          `json:"src_ip"`
	SrcPort     int             `json:"src_port"`
	DestIP      string          `json:"dest_ip"`
	DestPort    int             `json:"dest_port"`
	Proto       string          `json:"proto"`
	CommunityID string          `json:"community_id"`
	AppProto    string          `json:"app_proto"`
	Flow        json.RawMessage `json:"flow"`
	DNS         json.RawMessage `json:"dns"`
	HTTP        json.RawMessage `json:"http"`
	TLS         json.RawMessage `json:"tls"`
	Alert       json.RawMessage `json:"alert"`
	Anomaly     json.RawMessage `json:"anomaly"`
}

// Clean bounds a string to MaxFieldBytes, valid UTF-8 and no control
// characters.
func Clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > ngsensor.MaxFieldBytes {
		cut := ngsensor.MaxFieldBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

func addr(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func port(p int) int {
	if p < 0 || p > 65535 {
		return 0
	}
	return p
}

// fields copies the listed keys of a JSON object into details, prefixed.
func fields(raw json.RawMessage, prefix string, keys []string, details map[string]string) {
	if len(raw) == 0 {
		return
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return
	}
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case string:
			details[prefix+k] = Clean(x)
		case float64:
			details[prefix+k] = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			details[prefix+k] = strconv.FormatBool(x)
		}
	}
}

// Parse normalizes one EVE line. iface is used when the record names none.
func Parse(line []byte, iface string) (ngsensor.Event, error) {
	if len(line) > ngsensor.MaxLineBytes {
		return ngsensor.Event{}, errors.New("line exceeds the size limit")
	}
	var r record
	if err := json.Unmarshal(line, &r); err != nil {
		return ngsensor.Event{}, err
	}
	sum := sha256.Sum256(line)
	ev := ngsensor.Event{
		Interface: Clean(r.InIface), SrcIP: addr(r.SrcIP), SrcPort: port(r.SrcPort),
		DstIP: addr(r.DestIP), DstPort: port(r.DestPort), Proto: strings.ToLower(Clean(r.Proto)),
		CommunityID: Clean(r.CommunityID), AppProto: Clean(r.AppProto),
		Details: map[string]string{}, RawSHA256: hex.EncodeToString(sum[:]),
	}
	if ev.Interface == "" {
		ev.Interface = iface
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", r.Timestamp)
	if err != nil {
		if ts, err = time.Parse(time.RFC3339Nano, r.Timestamp); err != nil {
			return ngsensor.Event{}, errors.New("unparsable timestamp")
		}
	}
	ev.Time = ts.UTC()

	switch r.EventType {
	case "flow":
		ev.Kind = ngsensor.KindFlow
		fields(r.Flow, "flow.", []string{"pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "state", "reason", "start", "end"}, ev.Details)
	case "dns":
		ev.Kind = ngsensor.KindDNS
		fields(r.DNS, "dns.", []string{"type", "rrname", "rrtype", "rcode"}, ev.Details)
		if ev.Details["dns.rrname"] == "" {
			// EVE version 3 nests the question under "queries".
			var nested struct {
				Queries []struct {
					RRName string `json:"rrname"`
					RRType string `json:"rrtype"`
				} `json:"queries"`
			}
			if json.Unmarshal(r.DNS, &nested) == nil && len(nested.Queries) > 0 {
				ev.Details["dns.rrname"] = Clean(nested.Queries[0].RRName)
				ev.Details["dns.rrtype"] = Clean(nested.Queries[0].RRType)
			}
		}
	case "http":
		ev.Kind = ngsensor.KindHTTP
		fields(r.HTTP, "http.", []string{"hostname", "url", "http_method", "status", "http_user_agent", "length"}, ev.Details)
	case "tls":
		ev.Kind = ngsensor.KindTLS
		fields(r.TLS, "tls.", []string{"sni", "version", "ja3s"}, ev.Details)
	case "alert":
		ev.Kind = ngsensor.KindAlert
		fields(r.Alert, "alert.", []string{"signature_id", "signature", "category", "severity", "action", "rev"}, ev.Details)
		if ev.Details["alert.signature_id"] == "" {
			return ngsensor.Event{}, errors.New("alert without a signature id")
		}
	case "anomaly":
		ev.Kind = ngsensor.KindAnomaly
		fields(r.Anomaly, "anomaly.", []string{"type", "event", "layer"}, ev.Details)
	default:
		return ngsensor.Event{}, ErrSkip
	}
	if len(ev.Details) == 0 {
		ev.Details = nil
	}
	return ev, nil
}
