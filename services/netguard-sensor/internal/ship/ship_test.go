package ship

import "testing"

func TestBatch(t *testing.T) {
	lines := [][]byte{
		[]byte(`{"timestamp":"2026-11-24T10:00:00.000000+0000","event_type":"alert","in_iface":"wg-pf0","src_ip":"10.200.0.2","src_port":41000,"dest_ip":"10.255.0.1","dest_port":8000,"proto":"TCP","alert":{"signature_id":9100001,"signature":"PARALLELF canary: IDS self-test URI","severity":3}}`),
		[]byte(`{"timestamp":"2026-11-24T10:00:00.000000+0000","event_type":"stats"}`),
		[]byte(`not json`),
	}
	events, st := Batch(lines)
	if len(events) != 1 || st.NotKept != 1 || st.Malformed != 1 {
		t.Fatalf("events %d stats %+v", len(events), st)
	}
	if events[0].Kind != "alert" || events[0].Details["alert.signature_id"] != "9100001" {
		t.Fatalf("event %+v", events[0])
	}
}
