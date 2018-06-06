// Copyright 2018 Solarwinds Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package papertrail_go

import (
	"context"
	"fmt"
	"html/template"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	syslog "github.com/RackSec/srslog"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	keyFormat                   = "TS:%d-BODY:%s"
	defaultMaxDiskUsage         = 5    // disk usage in percentage
	defaultUltimateMaxDiskUsage = 99   // usage cannot go beyond this percentage value
	defaultBatchSize            = 1000 // records
	defaultDBLocation           = "./badger"
	cleanUpInterval             = 5 * time.Second
)

var (
	defaultWorkerCount = 10
	defaultRetention   = 24 * time.Hour
)

type logInfo struct {
	tmpl *template.Template
}

// LoggerInterface is the interface for all Papertrail logger types
type LoggerInterface interface {
	Log(string) error
	Close() error
}

type proto string

const (
	UDP     proto = "udp"
	TCP     proto = "tcp"
	TCP_TLS proto = "tcp+tls"
)

// Logger is a concrete type of LoggerInterface which collects and ships logs to Papertrail
type Logger struct {
	paperTrailURL string

	paperTrailProto proto

	tag string

	retentionPeriod time.Duration

	db *badger.DB

	logInfos map[string]*logInfo

	initialDiskUsage float64

	maxDiskUsage float64

	maxWorkers int

	loopFactor *loopFactor

	loopWait chan struct{}

	syslogWriter *syslog.Writer
}

// NewLogger does some ground work and returns an instance of LoggerInterface
func NewLogger(ctx context.Context, paperTrailProtocol, paperTrailURL, tag, dbLocation string, retention time.Duration,
	workerCount int, maxDiskUsage float64) (LoggerInterface, error) {
	if retention.Seconds() <= float64(0) {
		retention = defaultRetention
	}
	opts := badger.DefaultOptions
	if strings.TrimSpace(dbLocation) == "" {
		dbLocation = defaultDBLocation
	}
	opts.Dir = dbLocation
	opts.ValueDir = dbLocation

	db, err := badger.Open(opts)
	if err != nil {
		err = errors.Wrap(err, "error while opening a local db instance")
		logrus.Error(err)
		return nil, err
	}

	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}

	if maxDiskUsage <= 0 {
		maxDiskUsage = defaultMaxDiskUsage
	}

	logrus.Infof("Creating a new paper trail logger for url: %s", paperTrailURL)

	p := &Logger{
		paperTrailURL:    paperTrailURL,
		paperTrailProto:  getMappingProto(paperTrailProtocol),
		tag:              tag,
		retentionPeriod:  retention,
		maxWorkers:       workerCount * runtime.NumCPU(),
		maxDiskUsage:     maxDiskUsage,
		loopFactor:       newLoopFactor(true),
		db:               db,
		initialDiskUsage: diskUsage(),
		loopWait:         make(chan struct{}),
	}

	p.logInfos = map[string]*logInfo{}

	go p.flushLogs()
	go p.deleteExcess()
	go p.cleanup()
	return p, nil
}

// Log method receives log messages
func (p *Logger) Log(payload string) error {
	if len(payload) > 0 {
		guuid := uuid.NewV4()
		if err := p.db.Update(func(txn *badger.Txn) error {
			return txn.SetWithTTL([]byte(fmt.Sprintf(keyFormat, time.Now().UnixNano(), guuid)), []byte(payload), p.retentionPeriod)
		}); err != nil {
			err = errors.Wrapf(err, "error persisting log to local db")
			logrus.Error(err)
			return err
		}
	}
	return nil
}

func (p *Logger) sendLogs(data string) error {
	var err error
	if p.paperTrailProto == UDP || p.syslogWriter == nil {
		logrus.Debugf("protocol: %s, url: %s", p.paperTrailProto, p.paperTrailURL)
		p.syslogWriter, err = syslog.Dial(string(p.paperTrailProto), p.paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, p.tag)
		if err != nil {
			err = errors.Wrapf(err, "failed to dial syslog")
			logrus.Error(err)
			return err
		}
	}
	if p.paperTrailProto == UDP {
		defer p.syslogWriter.Close()
	}

	if err = p.syslogWriter.Info(data); err != nil {
		err = errors.Wrapf(err, "failed to send log msg to papertrail")
		logrus.Error(err)
		return err
	}
	return nil
}

// This should be run in a routine
func (p *Logger) flushLogs() {
	defer func() {
		p.loopWait <- struct{}{}
	}()
	for p.loopFactor.getBool() {
		hose := make(chan []byte, p.maxWorkers)
		wg := new(sync.WaitGroup)

		// workers
		for i := 0; i < p.maxWorkers; i++ {
			go p.flushWorker(hose, wg)
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
			err = errors.Wrapf(err, "flush logs - Error reading keys from db")
			logrus.Warn(err)
		}
		wg.Wait()
		close(hose)
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *Logger) flushWorker(hose chan []byte, wg *sync.WaitGroup) {
	for key := range hose {
		err := p.db.Update(func(txn *badger.Txn) error {
			item, err := txn.Get(key)
			if err != nil {
				if err == badger.ErrKeyNotFound {
					return nil
				}
				return err
			}
			var val []byte
			val, err = item.ValueCopy(val)
			if err != nil {
				if err == badger.ErrKeyNotFound {
					return nil
				}
				return err
			}
			err = p.sendLogs(string(val))
			if err == nil {
				logrus.Debugf("flushLogs, delete key: %s", key)
				err := txn.Delete(key)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			err = errors.Wrapf(err, "Error while deleting key: %s", key)
			logrus.Warn(err)
		}
		wg.Done()
	}
}

func (p *Logger) deleteExcess() {
	for p.loopFactor.getBool() {
		currentUsage := diskUsage()
		// if p.log.VerbosityLevel(config.DebugLevel) {
		// 	p.log.Infof("Current disk usage: %.2f %%", currentUsage)
		// 	p.log.Infof("DB folder size: %.2f MB", computeDirectorySizeInMegs(dbLocation))
		// }
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
					_ = txn.Delete(k)
					iterations--
					if iterations < 0 {
						break
					}
				}
				return nil
			})
			if err != nil {
				err = errors.Wrapf(err, "deleteExcess - Error while deleting")
				logrus.Warn(err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Close - closes the Logger instance
func (p *Logger) Close() error {
	p.loopFactor.setBool(false)
	defer close(p.loopWait)
	if p.paperTrailProto != UDP && p.syslogWriter != nil {
		if err := p.syslogWriter.Close(); err != nil {
			err = errors.Wrapf(err, "error while closing syslog writer")
			logrus.Error(err)
			return err
		}
	}
	time.Sleep(time.Second)
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			err = errors.Wrapf(err, "error while closing syslog writer")
			logrus.Error(err)
			return err
		}
	}
	<-p.loopWait
	return nil
}

func (p *Logger) cleanup() {
	for p.loopFactor.getBool() {
		if p.db != nil {
			logrus.Debug("cleanup - running GC")
			//_ = p.db.PurgeOlderVersions()
			_ = p.db.RunValueLogGC(0.99)
		}
		time.Sleep(cleanUpInterval)
	}
}

func diskUsage() float64 {
	var stat syscall.Statfs_t
	wd, _ := os.Getwd()
	_ = syscall.Statfs(wd, &stat)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := stat.Blocks * uint64(stat.Bsize)
	return (float64(used) / float64(used+avail)) * 100
}

//func computeDirectorySizeInMegs(fullPath string) float64 {
//	var sizeAccumulator int64
//	filepath.Walk(fullPath, func(path string, file os.FileInfo, err error) error {
//		if !file.IsDir() {
//			atomic.AddInt64(&sizeAccumulator, file.Size())
//		}
//		return nil
//	})
//	return float64(atomic.LoadInt64(&sizeAccumulator)) / (1024 * 1024)
//}

func getMappingProto(protocol string) proto {
	switch strings.TrimSpace(strings.ToLower(protocol)) {
	case "tcp+tls":
		return TCP_TLS
	case "tcp":
		return TCP
	default:
		return UDP
	}
}
