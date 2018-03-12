package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/docker/docker/daemon/logger"
	"github.com/pkg/errors"
)

type paperTrailLogReader struct {
	token string

	hostname             string
	containerID          string
	containerName        string
	containerImageID     string
	containerImageName   string
	containerCreatedTime time.Time

	httpClient *http.Client

	readers map[*logger.LogWatcher]struct{} // map for the active log followers
	mu      sync.Mutex
}

type PaperTrailResponse struct {
	MinID            string            `json:"min_id"`
	MaxID            string            `json:"max_id"`
	Events           []PaperTrailEvent `json:"events"`
	ReachedBeginning bool              `json:"reached_beginning"`
	ReachedEnd       bool              `json:"reached_end"`
	MinTimeAt        string            `json:"min_time_at"`
}

type PaperTrailEvent struct {
	ID                string `json:"id"`
	SourceIP          string `json:"source_ip"`
	Program           string `json:"program"`
	Message           string `json:"message"`
	ReceivedAt        string `json:"received_at"`
	GeneratedAt       string `json:"generated_at"`
	DisplayReceivedAt string `json:"display_received_at"`
	SourceID          int    `json:"source_id"`
	SourceName        string `json:"source_name"`
	Hostname          string `json:"hostname"`
	Severity          string `json:"severity"`
	Facility          string `json:"facility"`
}

const (
	LIMIT                       = "100"
	PAPERTRAIL_SEARCH_URL       = "https://papertrailapp.com/api/v1/events/search.json"
	PAPERTRAIL_TOKEN_HEADERNAME = "X-Papertrail-Token"
	PAPERTRAIL_MAX_LIMIT        = 10000
)

func newPaperTrailLogReader(logCtx logger.Info) (*paperTrailLogReader, error) {
	paperTrailToken := logCtx.Config["papertrail-token"]
	if strings.TrimSpace(paperTrailToken) == "" {
		err := errors.Errorf("Paper trail token cannot be empty.")
		log.Error(err)
		return nil, err
	}
	log.Info("Creating a new paper trail log reader")

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	p := &paperTrailLogReader{
		token: paperTrailToken,

		containerID:        logCtx.ContainerID,
		containerName:      strings.Replace(logCtx.ContainerName, "/", "", 1),
		containerImageID:   logCtx.ImageFullID(),
		containerImageName: logCtx.ImageName(),

		containerCreatedTime: logCtx.ContainerCreated,

		readers: map[*logger.LogWatcher]struct{}{},

		httpClient: client,
	}

	return p, nil
}

func (p *paperTrailLogReader) ReadLogs(config logger.ReadConfig) *logger.LogWatcher {
	logWatcher := logger.NewLogWatcher()

	go p.prepWatcher(logWatcher, config)
	return logWatcher
}

func (p *paperTrailLogReader) prepWatcher(watcher *logger.LogWatcher, config logger.ReadConfig) {
	defer close(watcher.Msg)

	p.mu.Lock()
	p.readers[watcher] = struct{}{}
	p.mu.Unlock()

	p.readLogs(watcher, config)

	p.mu.Lock()
	delete(p.readers, watcher)
	p.mu.Unlock()
}

func (p *paperTrailLogReader) readLogs(watcher *logger.LogWatcher, config logger.ReadConfig) {

	minID := ""
	maxID := ""
	reached_end := false

	hostname, err := os.Hostname()
	if err != nil {
		e := errors.Wrap(err, "failed to get the hostname")
		log.Error(e)
		watcher.Err <- err
		return
	}

	tailTrack := config.Tail
	var tailDone bool

	if tailTrack > PAPERTRAIL_MAX_LIMIT {
		e := errors.Wrap(err, fmt.Sprintf("Tail count cannot be greater than %d", PAPERTRAIL_MAX_LIMIT))
		log.Error(err)
		watcher.Err <- e
		return
	}

	log.Infof("Tail val: %d", tailTrack)

	for maxID == "" || (reached_end == false && minID != maxID) || config.Follow {

		req, err := http.NewRequest("GET", PAPERTRAIL_SEARCH_URL, nil)
		if err != nil {
			e := errors.Wrap(err, "Unable to create a request instance")
			log.Error(err)
			watcher.Err <- e
			return
		}

		q := req.URL.Query()
		q.Add("system_id", hostname)
		//q.Add("q", fmt.Sprintf("program:"+TAG_FORMAT, p.containerName, p.containerID, p.containerImageName, p.containerImageID))
		q.Add("q", fmt.Sprintf("program:%s", p.containerID))
		q.Add("tail", "false")

		log.Infof("Max id: %s", maxID)
		if maxID != "" {
			q.Add("min_id", maxID)
			q.Add("limit", LIMIT) // not limiting for the first run
		} else {
			log.Infof("Tail track count: %d", tailTrack)
			if tailTrack > 0 {
				q.Add("limit", strconv.Itoa(tailTrack))
				//q.Set("tail", "true")
				tailDone = true
			} else {
				if !config.Since.IsZero() {
					q.Add("min_time", fmt.Sprintf("%d", config.Since.Unix()))
				} else {
					q.Add("min_time", fmt.Sprintf("%d", p.containerCreatedTime.Unix())) // which is the container created time
				}
			}
		}

		if !config.Until.IsZero() {
			q.Add("max_time", fmt.Sprintf("%d", config.Until.Unix()))
		}

		req.URL.RawQuery = q.Encode()

		req.Header.Set(PAPERTRAIL_TOKEN_HEADERNAME, p.token)
		log.Infof("Computed url: %s", req.URL.String())
		resp, err := p.httpClient.Do(req)
		if err != nil {
			e := errors.Wrap(err, "Unable to call papertrail")
			log.Error(err)
			watcher.Err <- e
			return
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			e := errors.Wrap(err, "Unable to read the response body")
			log.Error(err)
			watcher.Err <- e
			return
		}

		pResp := &PaperTrailResponse{}

		err = json.Unmarshal(body, pResp)
		if err != nil {
			e := errors.Wrap(err, "Unable to parse the response body")
			log.Error(err)
			watcher.Err <- e
			return
		}
		log.Infof("Parsed Value min id: %s, max id: %s, reached_beginning: %t, reached_end: %t",
			pResp.MinID, pResp.MaxID, pResp.ReachedBeginning, pResp.ReachedEnd)
		log.Infof("Events: %v", pResp.Events)

		minID = pResp.MinID
		maxID = pResp.MaxID
		reached_end = pResp.ReachedEnd

		for _, event := range pResp.Events {
			msg := logger.NewMessage()
			msg.Line = []byte(event.Message + "\n") // docker is not appending new line after each msg when reading. . .
			msg.Timestamp, err = time.Parse(time.RFC3339, event.GeneratedAt)
			msg.Source = "stdout"
			watcher.Msg <- msg
		}

		if tailDone && !config.Follow {
			break
		}

		time.Sleep(time.Millisecond * 500)
	}
}
