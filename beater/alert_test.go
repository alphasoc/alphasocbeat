package beater

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/stretchr/testify/assert"
)

func TestBeatEvents_DNSEvents(t *testing.T) {
	response := `{
		"follow": "6-8263d641",
		"more": true,
		"alerts": [
		  {
			"eventType": "dns",
			"event": {
			  "ts": "2021-04-07T09:55:37Z",
			  "srcIP": "10.14.1.39",
			  "srcHost": "win-3xchk5-lp",
			  "srcMac": "da:23:68:50:c4:77",
			  "query": "hsxfrfokdkojcj.net",
			  "qtype": "A"
			},
			"threats": [
			  "suspicious_domain_volume",
			  "unreachable_domain_volume"
			],
			"wisdom": {
			  "flags": [
				"perplexing_domain",
				"unique",
				"unreachable_domain"
			  ],
			  "domain": "hsxfrfokdkojcj.net"
			}
		  }
		],
		"threats": {
			"suspicious_domain_volume": {
				"title": "Multiple requests to suspicious domains",
				"severity": 3
			},
			"unreachable_domain_volume": {
				"title": "Multiple requests to unreachable domains",
				"severity": 2
			}
		}
	}`

	body := &alertResponse{Alerts: &[]eventAlert{}}
	d := json.NewDecoder(strings.NewReader(response))
	if err := d.Decode(body); err != nil {
		t.Fatal("cannot decode response", err)
	}

	events := body.beatEvents()

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
				"alphasoc.threat.severity": severity(3),
				"alphasoc.threat.title":    "Multiple requests to suspicious domains",

				"alphasoc.event.src.ip":   "10.14.1.39",
				"alphasoc.event.src.host": "win-3xchk5-lp",
				"alphasoc.event.src.mac":  "da:23:68:50:c4:77",
				"alphasoc.event.query":    "hsxfrfokdkojcj.net",
				"alphasoc.event.qtype":    "A",

				"alphasoc.wisdom.flags": []string{
					"perplexing_domain",
					"unique",
					"unreachable_domain"},
				"alphasoc.wisdom.domain": "hsxfrfokdkojcj.net",
			},
		},
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 55, 37, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:55:37",
				"alphasoc.pipeline": "dns",

				"alphasoc.threat.value":    "unreachable_domain_volume",
				"alphasoc.threat.severity": severity(2),
				"alphasoc.threat.title":    "Multiple requests to unreachable domains",

				"alphasoc.event.src.ip":   "10.14.1.39",
				"alphasoc.event.src.host": "win-3xchk5-lp",
				"alphasoc.event.src.mac":  "da:23:68:50:c4:77",
				"alphasoc.event.query":    "hsxfrfokdkojcj.net",
				"alphasoc.event.qtype":    "A",

				"alphasoc.wisdom.flags": []string{
					"perplexing_domain",
					"unique",
					"unreachable_domain"},
				"alphasoc.wisdom.domain": "hsxfrfokdkojcj.net",
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
	response := `{
		"follow": "6-8263d641",
		"more": true,
		"alerts": [
			{
				"eventType": "ip",
				"event": {
					"ts": "2021-04-07T09:57:17Z",
					"srcIP": "10.100.92.3",
					"srcPort": 52065,
					"srcUser": "danknicholas",
					"destIP": "50.116.17.41",
					"destPort": 8009,
					"proto": "tcp",
					"bytesIn": 27307,
					"bytesOut": 5419,
					"app": "tls1.3",
					"action": "allowed",
					"duration": 2.48475075448
				},
				"threats": [
					"sinkholed_destination"
				],
				"wisdom": {
					"flags": [
					"sinkholed",
					"unusual_port"
					]
				}
			}
		],
		"threats": {
			"sinkholed_destination": {
				"title": "Traffic to a known sinkhole indicating infection",
				"severity": 4
			}
		}
	}`

	body := &alertResponse{Alerts: &[]eventAlert{}}
	d := json.NewDecoder(strings.NewReader(response))
	if err := d.Decode(body); err != nil {
		t.Fatal("cannot decode response", err)
	}

	events := body.beatEvents()

	expected := []beat.Event{
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 57, 17, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:57:17",
				"alphasoc.pipeline": "ip",

				"alphasoc.threat.value":    "sinkholed_destination",
				"alphasoc.threat.severity": severity(4),
				"alphasoc.threat.title":    "Traffic to a known sinkhole indicating infection",

				"alphasoc.event.src.ip":    "10.100.92.3",
				"alphasoc.event.src.port":  52065,
				"alphasoc.event.src.user":  "danknicholas",
				"alphasoc.event.dest.ip":   "50.116.17.41",
				"alphasoc.event.dest.port": 8009,
				"alphasoc.event.protocol":  "tcp",
				"alphasoc.event.app":       "tls1.3",
				"alphasoc.event.action":    "allowed",
				"alphasoc.event.duration":  2.48475075448,
				"alphasoc.event.bytes_in":  27307,
				"alphasoc.event.bytes_out": 5419,

				"alphasoc.wisdom.flags": []string{
					"sinkholed",
					"unusual_port",
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

func TestBeatEvents_TLSEvent(t *testing.T) {
	response := `{
		"follow": "6-8263d641",
		"more": true,
		"alerts": [
			{
				"eventType": "tls",
				"event": {
				  "ts": "2021-04-07T09:58:18Z",
				  "srcIP": "10.36.86.38",
				  "srcPort": 57849,
				  "certHash": "9fcc5c1e8ec32f56e975ba43c923dbfa16a8f946",
				  "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
				  "subject": "C=US,ST=TX,L=Texas,O=lol,OU=,CN=topbackupintheworld.com",
				  "validFrom": "2021-03-30T00:34:02Z",
				  "validTo": "2021-05-29T00:34:02Z",
				  "destIP": "",
				  "destPort": 0,
				  "ja3": "724dedf93fb5a3636a0f1ee8fcec8801",
				  "ja3s": "015535be754766257f9bfdf3470cd428e0f1cfd4"
				},
				"threats": [
				  "c2_communication"
				],
				"wisdom": {
				  "flags": [
					"c2"
				  ],
				  "labels": [
					"c2:Cobalt Strike",
					"c2:Ryuk"
				  ]
				}
			  }
		],
		"threats": {
			"c2_communication": {
				"title": "C2 communication attempt indicating infection",
				"severity": 5
			}
		}
	}`

	body := &alertResponse{Alerts: &[]eventAlert{}}
	d := json.NewDecoder(strings.NewReader(response))
	if err := d.Decode(body); err != nil {
		t.Fatal("cannot decode response", err)
	}

	events := body.beatEvents()

	expected := []beat.Event{
		{
			Timestamp: time.Date(2021, time.April, 7, 9, 58, 18, 0, time.UTC),
			Fields: common.MapStr{
				"alphasoc.event.ts": "2021-04-07 09:58:18",
				"alphasoc.pipeline": "tls",

				"alphasoc.threat.value":    "c2_communication",
				"alphasoc.threat.severity": severity(5),
				"alphasoc.threat.title":    "C2 communication attempt indicating infection",

				"alphasoc.event.src.ip":     "10.36.86.38",
				"alphasoc.event.src.port":   57849,
				"alphasoc.event.dest.port":  0,
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
