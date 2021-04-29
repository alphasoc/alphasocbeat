package beater

import (
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
)

type severity int

// alertResponse represents API response with alerts
type alertResponse struct {
	Follow string `json:"follow"`
	More   bool   `json:"more"`
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`

	Alerts *[]eventAlert `json:"alerts,omitempty"`

	Threats map[string]threatInfo `json:"threats"`
}

type eventAlert struct {
	Type    string                 `json:"eventType"`
	Event   map[string]interface{} `json:"event"`
	Threats []string               `json:"threats"`
	Wisdom  map[string]interface{} `json:"wisdom"`
}

type threatInfo struct {
	Title    string   `json:"title"`
	Severity severity `json:"severity"`
	Policy   bool     `json:"policy,omitempty"`
}

// beatEvents converts alerts from alertResponse to beat events
// with proper index fields mapping
func (ar *alertResponse) beatEvents() []beat.Event {
	events := []beat.Event{}

	for _, a := range *ar.Alerts {
		// Create separate document for each threat
		for _, threat := range a.Threats {
			// Parse event timestamp
			ts := time.Now()
			t, ok := a.Event["ts"]
			if ok {
				parsed, err := time.Parse(time.RFC3339, t.(string))
				if err == nil {
					ts = parsed
				}
			}

			beatEvent := beat.Event{
				Timestamp: ts,
				Fields: common.MapStr{
					"alphasoc.event.ts": ts.Format("2006-01-02 15:04:05"),
					"alphasoc.pipeline": a.Type,
				},
			}

			// Add known event fields values
			for k, v := range a.Event {
				if v == "" {
					continue
				}

				if mappedKey, ok := eventFields[k]; ok {
					beatEvent.Fields[mappedKey] = v

					if k == "destIP" && a.Type == "ip" {
						beatEvent.Fields["alphasoc.event.dest.ip_raw"] = v
					}

					if k == "url" && a.Type == "http" {
						beatEvent.Fields["alphasoc.event.dest.url_raw"] = v
					}
				}
			}

			// Add known wisdom fields values
			for k, v := range a.Wisdom {
				if mappedKey, ok := wisdomFields[k]; ok {
					beatEvent.Fields[mappedKey] = v
				}
			}

			beatEvent.Fields["alphasoc.threat.value"] = threat
			if t, ok := ar.Threats[threat]; ok {
				beatEvent.Fields["alphasoc.threat.severity"] = t.Severity
				beatEvent.Fields["alphasoc.threat.title"] = t.Title
			}

			events = append(events, beatEvent)
		}
	}

	return events
}
