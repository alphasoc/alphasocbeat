package beater

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alphasoc/alphasoc-go"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/stretchr/testify/assert"
)

func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func int32Ptr(i int32) *int32 {
	return &i
}

func int64Ptr(i int64) *int64 {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}

func boolPtr(b bool) *bool {
	return &b
}

func TestBeatEvents_DNSEvents(t *testing.T) {
	resp := &alphasoc.Alerts{
		Follow: stringPtr("6-8263d641"), More: boolPtr(true),
		Alerts: &[]alphasoc.Alert{
			{
				EventType: stringPtr("dns"),
				Event:     []byte(`{"ts": "2021-04-07T09:55:37Z", "srcIP": "10.14.1.39", "srcHost": "win-3xchk5-lp", "srcMac": "da:23:68:50:c4:77", "query": "hsxfrfokdkojcj.net", "qtype": "A"}`),
				Threats:   &[]string{"suspicious_domain_volume", "unreachable_domain_volume"},
				Wisdom:    &alphasoc.Wisdom{Flags: &[]string{"perplexing_domain", "unique", "unreachable_domain"}, Domain: stringPtr("hsxfrfokdkojcj.net")},
			},
		},
		Threats: &map[string]alphasoc.Threat{
			"suspicious_domain_volume":  {Title: "Multiple requests to suspicious domains", Severity: 3},
			"unreachable_domain_volume": {Title: "Multiple requests to unreachable domains", Severity: 2},
		},
	}

	bt := &alphasocbeat{log: logp.L()}

	events := bt.beatEvents(resp)

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	}

	expected := []beat.Event{
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 55, 37, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:55:37",
				"alphasoc.pipeline": "dns",

				"alphasoc.threat.value":    "suspicious_domain_volume",
				"alphasoc.threat.severity": 3,
				"alphasoc.threat.title":    "Multiple requests to suspicious domains",

				"source.ip":            "10.14.1.39",
				"source.address":       "win-3xchk5-lp",
				"source.mac":           "da:23:68:50:c4:77",
				"alphasoc.event.query": "hsxfrfokdkojcj.net",
				"dns.question.type":    "A",

				"alphasoc.wisdom.flags": []string{
					"perplexing_domain",
					"unique",
					"unreachable_domain"},
				"destination.domain":     "hsxfrfokdkojcj.net",
				"alphasoc.wisdom.labels": interface{}(nil),
			},
		},
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 55, 37, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:55:37",
				"alphasoc.pipeline": "dns",

				"alphasoc.threat.value":    "unreachable_domain_volume",
				"alphasoc.threat.severity": 2,
				"alphasoc.threat.title":    "Multiple requests to unreachable domains",

				"source.ip":            "10.14.1.39",
				"source.address":       "win-3xchk5-lp",
				"source.mac":           "da:23:68:50:c4:77",
				"alphasoc.event.query": "hsxfrfokdkojcj.net",
				"dns.question.type":    "A",

				"alphasoc.wisdom.flags": []string{
					"perplexing_domain",
					"unique",
					"unreachable_domain"},
				"destination.domain":     "hsxfrfokdkojcj.net",
				"alphasoc.wisdom.labels": nil,
			},
		},
	}

	eventsJSON, err := json.Marshal(events)
	if err != nil {
		t.Fatal("marshaling events to json")
	}

	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal("marshaling expected to json")
	}

	assert.JSONEq(t, string(expectedJSON), string(eventsJSON))
}

func TestBeatEvents_IPEvent(t *testing.T) {
	resp := &alphasoc.Alerts{
		Follow: stringPtr("6-8263d641"), More: boolPtr(true),
		Alerts: &[]alphasoc.Alert{
			{
				EventType: stringPtr("ip"),
				Event:     []byte(`{"ts": "2021-04-07T09:57:17Z", "srcIP": "10.100.92.3", "srcPort": 52065, "srcUser": "danknicholas", "destIP": "50.116.17.41", "destPort": 8009, "proto": "tcp", "bytesIn": 27307, "bytesOut": 5419, "app": "tls1.3", "action": "allowed", "duration": 2.48475075448}`),
				Threats:   &[]string{"sinkholed_destination"},
				Wisdom:    &alphasoc.Wisdom{Flags: &[]string{"sinkholed", "unusual_port"}},
			},
		},
		Threats: &map[string]alphasoc.Threat{
			"sinkholed_destination": {Title: "Traffic to a known sinkhole indicating infection", Severity: 4},
		},
	}

	bt := &alphasocbeat{log: logp.L()}

	events := bt.beatEvents(resp)

	expected := []beat.Event{
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 57, 17, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:57:17",
				"alphasoc.pipeline": "ip",

				"alphasoc.threat.value":    "sinkholed_destination",
				"alphasoc.threat.severity": 4,
				"alphasoc.threat.title":    "Traffic to a known sinkhole indicating infection",

				"source.ip":                  "10.100.92.3",
				"source.port":                52065,
				"alphasoc.event.src.user":    "danknicholas",
				"destination.ip":             "50.116.17.41",
				"alphasoc.event.dest.ip_raw": "50.116.17.41",
				"destination.port":           8009,
				"network.transport":          "tcp",
				"network.protocol":           "tls1.3",
				"alphasoc.event.action":      "allowed",
				"event.duration":             2.48475075448,
				"destination.bytes":          27307,
				"source.bytes":               5419,

				"alphasoc.wisdom.flags": []string{
					"sinkholed",
					"unusual_port",
				},
				"destination.domain":     nil,
				"alphasoc.wisdom.labels": nil,
			},
		},
	}

	eventsJSON, err := json.Marshal(events)
	if err != nil {
		t.Fatal("marshaling events to json")
	}

	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal("marshaling expected to json")
	}

	assert.JSONEq(t, string(expectedJSON), string(eventsJSON))
}

func TestBeatEvents_TLSEvent(t *testing.T) {
	resp := &alphasoc.Alerts{
		Follow: stringPtr("6-8263d641"), More: boolPtr(true),
		Alerts: &[]alphasoc.Alert{
			{
				EventType: stringPtr("tls"),
				Event:     []byte(`{"ts": "2021-04-07T09:58:18Z", "srcIP": "10.36.86.38", "srcPort": 57849, "certHash": "9fcc5c1e8ec32f56e975ba43c923dbfa16a8f946", "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US", "subject": "C=US,ST=TX,L=Texas,O=lol,OU=,CN=topbackupintheworld.com", "validFrom": "2021-03-30T00:34:02Z", "validTo": "2021-05-29T00:34:02Z", "destIP": "", "destPort": 0,"ja3": "724dedf93fb5a3636a0f1ee8fcec8801", "ja3s": "015535be754766257f9bfdf3470cd428e0f1cfd4"}`),
				Threats:   &[]string{"c2_communication"},
				Wisdom:    &alphasoc.Wisdom{Flags: &[]string{"c2"}, Labels: &[]string{"c2:Cobalt Strike", "c2:Ryuk"}},
			},
		},
		Threats: &map[string]alphasoc.Threat{
			"c2_communication": {Title: "C2 communication attempt indicating infection", Severity: 5},
		},
	}

	bt := &alphasocbeat{log: logp.L()}

	events := bt.beatEvents(resp)

	expected := []beat.Event{
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 58, 18, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:58:18",
				"alphasoc.pipeline": "tls",

				"alphasoc.threat.value":    "c2_communication",
				"alphasoc.threat.severity": 5,
				"alphasoc.threat.title":    "C2 communication attempt indicating infection",

				"source.ip":                 "10.36.86.38",
				"source.port":               57849,
				"destination.port":          0,
				"alphasoc.event.cert_hash":  "9fcc5c1e8ec32f56e975ba43c923dbfa16a8f946",
				"alphasoc.event.issuer":     "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
				"alphasoc.event.subject":    "C=US,ST=TX,L=Texas,O=lol,OU=,CN=topbackupintheworld.com",
				"alphasoc.event.valid_from": "2021-03-30T00:34:02Z",
				"alphasoc.event.valid_to":   "2021-05-29T00:34:02Z",
				"alphasoc.event.ja3":        "724dedf93fb5a3636a0f1ee8fcec8801",
				"alphasoc.event.ja3s":       "015535be754766257f9bfdf3470cd428e0f1cfd4",

				"alphasoc.wisdom.flags": []string{
					"c2",
				},
				"destination.domain": nil,
				"alphasoc.wisdom.labels": []string{
					"c2:Cobalt Strike",
					"c2:Ryuk",
				},
			},
		},
	}

	eventsJSON, err := json.Marshal(events)
	if err != nil {
		t.Fatal("marshaling events to json")
	}

	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal("marshaling expected to json")
	}

	assert.JSONEq(t, string(expectedJSON), string(eventsJSON))
}
