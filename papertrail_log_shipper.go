package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	//syslog "github.com/RackSec/srslog"

	"log/syslog"

	"github.com/boltdb/bolt"
	"github.com/docker/docker/daemon/logger"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

const (
	name       = "Docker Paper Trail Logger"
	bucketName = "docker"
)

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

	db *bolt.DB
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

	db, err := bolt.Open(fmt.Sprintf("/tmp/%s.db", logCtx.ContainerID), 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		err := errors.Errorf("Unable to open a database for papertrail log processing.")
		log.Error(err)
		return nil, err
	}

	log.Infof("Creating a new paper trail logger for url: %s", paperTrailURL)

	p := &PaperTrailLogger{
		paperTrailURL: paperTrailURL,
		token:         paperTrailToken,
		httpClient:    client,

		containerID:          logCtx.ContainerID,
		containerCreatedTime: logCtx.ContainerCreated,

		readers: map[*logger.LogWatcher]struct{}{},

		db: db,
	}
	go p.flushLogs()
	return p, nil
}

func (p *PaperTrailLogger) Log(msg *logger.Message) error {
	if len(msg.Line) > 0 {
		err := p.db.Update(func(tx *bolt.Tx) error {
			buc, err := tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return fmt.Errorf("Unable to create bucket error: %v", err)
			}
			err = buc.Put([]byte(fmt.Sprintf("%d", time.Now().UnixNano())), msg.Line)
			return err
		})
		if err != nil {
			e := errors.Wrap(err, fmt.Sprintf("Unable to store the log for further processing: %s", string(msg.Line)))
			log.Error(e)
			return e
		}
	}
	return nil
}
func (p *PaperTrailLogger) sendLogs(data []byte) error {
	var err error
	writer, err := syslog.Dial("udp", p.paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, p.containerID)
	if err != nil {
		e := errors.Wrap(err, "failed to dial syslog")
		log.Error(e)
		return e
	}
	err = writer.Info(string(data))
	if err != nil {
		e := errors.Wrap(err, "failed to send log msg to papertrail")
		log.Error(e)
		return e
	}
	return nil
}

// This should be run in a routine
func (p *PaperTrailLogger) flushLogs() {
	var err error
	for p.db != nil {
		err = p.db.Update(func(tx *bolt.Tx) error {
			// Assume bucket exists and has keys
			b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return fmt.Errorf("Unable to create bucket error: %v", err)
			}

			b.ForEach(func(k, v []byte) error {
				err = p.sendLogs(v)
				if err == nil {
					err = b.Delete(k)
				}
				return err
			})
			return nil
		})
		if err != nil {
			e := errors.Wrap(err, "Error reading the data in the DB and shipping logs")
			log.Error(e)
		}
		time.Sleep(time.Second)
	}
}

func (p *PaperTrailLogger) Name() string {
	return name
}
func (p *PaperTrailLogger) Close() error {
	var err error
	if p.writer != nil {
		err = p.writer.Close()
		if err != nil {
			e := errors.Wrap(err, "failed to close papertrail logger")
			log.Error(e)
			return e
		}
	}
	if p.db != nil {
		err = p.db.Close()
		p.db = nil // this will stop the flush loop
	}
	return err
}
