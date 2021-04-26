package beater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/backoff"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/alphasoc/alphasocbeat/checkpoint"
	"github.com/alphasoc/alphasocbeat/config"
)

// alphasocbeat configuration.
type alphasocbeat struct {
	done       chan struct{}
	config     config.Config
	client     beat.Client
	checkpoint *checkpoint.Checkpoint

	apiURL string
	apiKey string

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
		apiURL:     c.APIURL,
		apiKey:     c.APIKey,
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

	req, err := http.NewRequest("GET", bt.apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Encoding", "gzip")
	req.URL.User = url.User(bt.apiKey)

	back := backoff.NewExpBackoff(bt.done, 1*time.Second, 60*time.Second)
	for {
		if !back.Wait() {
			return nil
		}

		q := req.URL.Query()
		q.Del("follow")
		if follow != "" {
			q.Add("follow", follow)
			req.URL.RawQuery = q.Encode()
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			bt.log.Errorw("http.Do", logp.Error(err))
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			continue
		} else if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("response status code is not 200, got %v", resp.Status)
		}

		body := &alertResponse{Alerts: &[]eventAlert{}}
		d := json.NewDecoder(resp.Body)
		if err := d.Decode(body); err != nil {
			return fmt.Errorf("json.Decode: %w", err)
		}

		follow = body.Follow
		bt.checkpoint.Persist(follow)

		bt.client.PublishAll(body.beatEvents())

		if body.More {
			back.Reset()
		}
	}
}

// Stop stops alphasocbeat.
func (bt *alphasocbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}
