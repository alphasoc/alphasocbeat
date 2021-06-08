package beater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/backoff"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/alphasoc/alphasoc-go"
	"github.com/alphasoc/alphasocbeat/checkpoint"
	"github.com/alphasoc/alphasocbeat/config"
)

const APIPath = "/v1/alerts"

// alphasocbeat configuration.
type alphasocbeat struct {
	done       chan struct{}
	config     config.Config
	client     beat.Client
	checkpoint *checkpoint.Checkpoint

	apiClient *alphasoc.Client

	log *logp.Logger
}

// New creates an instance of alphasocbeat.
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	c := config.Config{}
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	cp, err := checkpoint.NewCheckpoint(c.RegistryFile, 1, 1*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("creating checkpoint: %w", err)
	}

	bt := &alphasocbeat{
		done:       make(chan struct{}),
		config:     c,
		checkpoint: cp,
		apiClient:  alphasoc.NewClient(c.APIKey),
		log:        logp.NewLogger("alphasocbeat"),
	}

	return bt, nil
}

// Run starts alphasocbeat.
func (bt *alphasocbeat) Run(b *beat.Beat) error {
	bt.log.Info("alphasocbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	follow := bt.checkpoint.State()

	back := backoff.NewExpBackoff(bt.done, 1*time.Second, 60*time.Second)
	for {
		if !back.Wait() {
			return nil
		}

		alerts, err := bt.apiClient.GetAlerts(follow)
		if err != nil {
			if asocErr, ok := err.(alphasoc.APIError); ok {
				if asocErr.StatusCode == http.StatusTooManyRequests {
					continue
				}
			}

			return fmt.Errorf("retrieving alerts: %w", err)
		}

		follow = alerts.GetFollow()
		bt.checkpoint.Persist(follow)

		if alerts.GetMore() {
			back.Reset()
		}

		bt.client.PublishAll(bt.beatEvents(alerts))
	}
}

// Stop stops alphasocbeat.
func (bt *alphasocbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

// beatEvents converts alerts to beat events
// with proper index fields mapping
func (bt *alphasocbeat) beatEvents(alerts *alphasoc.Alerts) []beat.Event {
	events := []beat.Event{}

	for _, a := range *alerts.Alerts {
		// parse event as map[string]interface{}
		event := map[string]interface{}{}
		err := json.Unmarshal(a.Event, &event)
		if err != nil {
			bt.log.Errorf("parsing event", err)
			continue
		}

		// Create separate document for each threat
		for _, threat := range *a.Threats {
			// Parse event timestamp
			ts := time.Now()
			t, ok := event["ts"]
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
					"alphasoc.pipeline": a.GetEventType(),
				},
			}

			// Add known event fields values
			for k, v := range event {
				if v == "" {
					continue
				}

				if mappedKey, ok := eventFields[k]; ok {
					beatEvent.Fields[mappedKey] = v

					if k == "destIP" && a.GetEventType() == "ip" {
						beatEvent.Fields["alphasoc.event.dest.ip_raw"] = v
					}

					if k == "url" && a.GetEventType() == "http" {
						beatEvent.Fields["alphasoc.event.dest.url_raw"] = v
					}
				}
			}

			// Add wisdom fields
			if a.Wisdom != nil {
				beatEvent.Fields["destination.domain"] = a.Wisdom.Domain
				beatEvent.Fields["alphasoc.wisdom.flags"] = a.Wisdom.Flags
				beatEvent.Fields["alphasoc.wisdom.labels"] = a.Wisdom.Labels
			}

			// Add threat fields
			beatEvent.Fields["alphasoc.threat.value"] = threat
			if t, ok := (*alerts.Threats)[threat]; ok {
				beatEvent.Fields["alphasoc.threat.severity"] = t.Severity
				beatEvent.Fields["alphasoc.threat.title"] = t.Title
			}

			events = append(events, beatEvent)
		}
	}

	return events
}
