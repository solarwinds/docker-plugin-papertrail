package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	//syslog "github.com/RackSec/srslog"

	"log/syslog"

	"github.com/docker/docker/daemon/logger"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

const name = "Docker Paper Trail Logger"

type PaperTrailLogger struct {
	paperTrailURL string
	token         string
	writer        *syslog.Writer

	hostname             string
	containerID          string
	containerCreatedTime time.Time

	httpClient *http.Client

	readers map[*logger.LogWatcher]struct{} // map for the active log followers
	mu      sync.Mutex
}

func NewPaperTrailLogger(logCtx logger.Info) (*PaperTrailLogger, error) {
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
	}

	client := &http.Client{
		Transport: transport,
	}

	paperTrailURL := logCtx.Config["papertrail-url"]
	if strings.TrimSpace(paperTrailURL) == "" {
		err := errors.Errorf("Paper trail url cannot be empty.")
		log.Error(err)
		return nil, err
	}

	paperTrailToken := logCtx.Config["papertrail-token"]
	if strings.TrimSpace(paperTrailToken) == "" {
		err := errors.Errorf("Paper trail token cannot be empty.")
		log.Error(err)
		return nil, err
	}

	log.Infof("Creating a new paper trail logger for url: %s", paperTrailURL)

	return &PaperTrailLogger{
		paperTrailURL: paperTrailURL,
		token:         paperTrailToken,
		httpClient:    client,

		containerID:          logCtx.ContainerID,
		containerCreatedTime: logCtx.ContainerCreated,

		readers: map[*logger.LogWatcher]struct{}{},
	}, nil
}

func (p *PaperTrailLogger) Log(msg *logger.Message) error {
	if len(msg.Line) > 0 {
		writer, err := syslog.Dial("udp", p.paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, p.containerID)
		if err != nil {
			e := errors.Wrap(err, "failed to dial syslog")
			log.Error(e)
			return e
		}

		if msg.Source == "stderr" || msg.Err != nil {
			err = writer.Err(string(msg.Line))
		} else {
			err = writer.Info(string(msg.Line))
		}
		if err != nil {
			e := errors.Wrap(err, "failed to write log msg")
			log.Error(e)
			return e
		}
	}
	return nil
}
func (p *PaperTrailLogger) Name() string {
	return name
}
func (p *PaperTrailLogger) Close() error {
	if p.writer != nil {
		err := p.writer.Close()
		if err != nil {
			e := errors.Wrap(err, "failed to close papertrail logger")
			log.Error(e)
			return e
		}
	}
	return nil
}
