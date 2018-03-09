package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	syslog "github.com/RackSec/srslog"

	"github.com/dgraph-io/badger"
	"github.com/docker/docker/daemon/logger"
	"github.com/satori/go.uuid"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

const (
	name                        = "Docker Paper Trail Logger"
	defaultRetention            = "24h"
	keyFormat                   = "TS:%d-BODY:%s"
	defaultMaxWorkers           = 5
	defaultMaxDiskUsage         = 5  // disk usage in percentage
	defaultUltimateMaxDiskUsage = 99 // percentage
	defaultBatchSize            = 1000
	cleanUpInterval             = 5 * time.Second
)

type paperTrailLogger struct {
	paperTrailProto string
	paperTrailURL   string
	token           string

	retentionPeriod time.Duration

	writer *syslog.Writer

	hostname             string
	containerID          string
	containerCreatedTime time.Time

	httpClient *http.Client

	readers map[*logger.LogWatcher]struct{} // map for the active log followers
	mu      sync.Mutex

	db *badger.DB

	loopFactor bool

	initialDiskUsage float64
	maxDiskUsage     float64

	maxWorkers int

	dbLocation string
}

func newPaperTrailLogger(logCtx logger.Info) (*paperTrailLogger, error) {
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

	paperTrailProto := logCtx.Config["papertrail-proto"]
	if strings.TrimSpace(paperTrailProto) == "" {
		// Default to UDP for backwards compatability
		paperTrailProto = "udp"
		log.Info("papertrail-proto not set. Defaulting to udp.")
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

	logRetentionStr := logCtx.Config["papertrail-log-retention"]
	if strings.TrimSpace(logRetentionStr) == "" {
		logRetentionStr = defaultRetention
	}

	var maxDiskUsage float64
	maxDiskUsageStr := logCtx.Config["papertrail-max-diskusage"]
	if strings.TrimSpace(maxDiskUsageStr) != "" {
		maxDiskUsage, _ = strconv.ParseFloat(maxDiskUsageStr, 64)
	}
	if maxDiskUsage <= 0 {
		maxDiskUsage = defaultMaxDiskUsage
	}

	retention := parseRetention(logRetentionStr)

	dbLocation := fmt.Sprintf("/tmp/%s.db", logCtx.ContainerID)

	opts := badger.DefaultOptions
	opts.Dir = dbLocation
	opts.ValueDir = dbLocation

	db, err := badger.Open(opts)
	if err != nil {
		err := errors.Errorf("Unable to open a database for papertrail log processing.")
		log.Error(err)
		return nil, err
	}

	log.Infof("Creating a new paper trail logger for url: %s", paperTrailURL)

	p := &paperTrailLogger{
		paperTrailProto: paperTrailProto,
		paperTrailURL:   paperTrailURL,
		token:           paperTrailToken,
		retentionPeriod: time.Duration(retention) * time.Hour,

		httpClient: client,

		containerID:          logCtx.ContainerID,
		containerCreatedTime: logCtx.ContainerCreated,

		readers: map[*logger.LogWatcher]struct{}{},

		db:         db,
		loopFactor: true,

		maxWorkers: defaultMaxWorkers,

		initialDiskUsage: diskUsage(),
		dbLocation:       dbLocation,

		maxDiskUsage: maxDiskUsage,
	}
	go p.flushLogs()
	go p.deleteExcess()
	go p.cleanup()

	return p, nil
}

func (p *paperTrailLogger) Log(msg *logger.Message) error {
	if len(msg.Line) > 0 {
		err := p.db.Update(func(txn *badger.Txn) error {
			uuid, _ := uuid.NewV4()
			err := txn.SetWithTTL([]byte(fmt.Sprintf(keyFormat, time.Now().UnixNano(), uuid)), msg.Line, p.retentionPeriod)
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
func (p *paperTrailLogger) sendLogs(data []byte) error {
	var err error
	writer, err := syslog.Dial(p.paperTrailProto, p.paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, p.containerID)
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
	defer writer.Close()
	return nil
}

// This should be run in a routine
func (p *paperTrailLogger) flushLogs() {
	for p.loopFactor {
		hose := make(chan []byte, p.maxWorkers)
		var wg sync.WaitGroup

		// workers
		for i := 0; i < p.maxWorkers; i++ {
			go func(worker int) {
				log.Debugf("AO - flushlogs, worker %d initialized.", (worker + 1))
				defer log.Debugf("AO - flushlogs, worker %d signing off.", (worker + 1))

				for key := range hose {
					log.Debugf("AO - flushlogs, worker %d took the job.", (worker + 1))

					err := p.db.Update(func(txn *badger.Txn) error {
						item, err := txn.Get(key)
						if err != nil {
							if err == badger.ErrKeyNotFound {
								return nil
							} else {
								return err
							}
						}
						var val []byte
						val, err = item.ValueCopy(val)
						if err != nil {
							if err == badger.ErrKeyNotFound {
								return nil
							} else {
								return err
							}
						}
						err = p.sendLogs(val)
						if err == nil {
							log.Debugf("AO - flushLogs, delete key: %s", key)
							err := txn.Delete(key)
							if err != nil {
								return err
							}
							return nil
						}
						return nil
					})
					if err != nil {
						log.Errorf("Error while deleting key: %s - error: %v", key, err)
					}
					wg.Done()
				}
			}(i)
		}

		err := p.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				k := make([]byte, len(item.Key()))
				copy(k, item.Key())
				wg.Add(1)
				hose <- k
			}
			return nil
		})
		if err != nil {
			log.Errorf("AO - flush logs - Error reading keys from db: ", err)
		}
		wg.Wait()
		close(hose)
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *paperTrailLogger) Name() string {
	return name
}
func (p *paperTrailLogger) Close() error {
	var err error
	p.loopFactor = false
	time.Sleep(time.Second)
	if p.db != nil {
		err = p.db.Close()
	}
	return err
}

func (p *paperTrailLogger) deleteExcess() {
	for p.loopFactor {
		currentUsage := diskUsage()
		log.Debugf("Current disk usage: %.2f %%", currentUsage)
		log.Debugf("DB folder size: %.2f MB", computeDirectorySizeInMegs(p.dbLocation))
		if currentUsage > p.initialDiskUsage+p.maxDiskUsage || currentUsage > defaultUltimateMaxDiskUsage {
			// delete from beginning
			iterations := defaultBatchSize
			err := p.db.View(func(txn *badger.Txn) error {
				opts := badger.DefaultIteratorOptions
				opts.PrefetchValues = false
				it := txn.NewIterator(opts)
				defer it.Close()
				for it.Rewind(); it.Valid(); it.Next() {
					item := it.Item()
					k := make([]byte, len(item.Key()))
					copy(k, item.Key())
					txn.Delete(k)
					iterations--
					if iterations < 0 {
						break
					}
				}
				return nil
			})
			if err != nil {
				log.Errorf("AO - deleteExcess - Error while deleting - error: %v", err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (p *paperTrailLogger) cleanup() {
	for p.loopFactor {
		if p.db != nil {
			log.Debug("AO - cleanup - running GC")
			p.db.PurgeOlderVersions()
			p.db.RunValueLogGC(0.99)
		}
		time.Sleep(cleanUpInterval)
	}
}

func parseRetention(logRetentionStr string) time.Duration {
	retention, err := time.ParseDuration(logRetentionStr)
	if err != nil {
		retention, _ = time.ParseDuration(defaultRetention)
	}
	if retention.Seconds() <= float64(0) {
		retention, _ = time.ParseDuration(defaultRetention)
	}
	return retention
}

func diskUsage() float64 {
	var stat syscall.Statfs_t
	wd, _ := os.Getwd()
	syscall.Statfs(wd, &stat)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := stat.Blocks * uint64(stat.Bsize)
	return (float64(used) / float64(used+avail)) * 100
}

func computeDirectorySizeInMegs(fullPath string) float64 {
	var sizeAccumulator int64
	filepath.Walk(fullPath, func(path string, file os.FileInfo, err error) error {
		if !file.IsDir() {
			atomic.AddInt64(&sizeAccumulator, file.Size())
		}
		return nil
	})
	return float64(atomic.LoadInt64(&sizeAccumulator)) / (1024 * 1024)
}
