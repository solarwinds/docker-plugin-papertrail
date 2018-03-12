package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/solarwinds/papertrail-go"

	"github.com/docker/docker/daemon/logger"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

const (
	name       = "Docker Paper Trail Logger"
	TAG_FORMAT = "%s (%s)"
)

type paperTrailLogShipper struct {
	paperTrailClient papertrail_go.LoggerInterface
}

func newPaperTrailLogShipper(logCtx logger.Info) (*paperTrailLogShipper, error) {
	paperTrailProto := logCtx.Config["papertrail-proto"]

	paperTrailURL := logCtx.Config["papertrail-url"]
	if strings.TrimSpace(paperTrailURL) == "" {
		err := errors.Errorf("Paper trail url cannot be empty.")
		log.Error(err)
		return nil, err
	}

	var retention time.Duration
	logRetentionStr := logCtx.Config["papertrail-log-retention"]
	if strings.TrimSpace(logRetentionStr) != "" {
		retention, _ = time.ParseDuration(logRetentionStr)
	}

	var maxDiskUsage float64
	maxDiskUsageStr := logCtx.Config["papertrail-max-diskusage"]
	if strings.TrimSpace(maxDiskUsageStr) != "" {
		maxDiskUsage, _ = strconv.ParseFloat(maxDiskUsageStr, 64)
	}

	var workerCount int
	workerCountStr := logCtx.Config["papertrail-worker-count"]
	if strings.TrimSpace(workerCountStr) != "" {
		workerCount, _ = strconv.Atoi(workerCountStr)
	}

	dbLocation := fmt.Sprintf("/tmp/%s.db", logCtx.ContainerID)
	//tag := fmt.Sprintf(TAG_FORMAT, strings.Replace(logCtx.ContainerName, "/", "", 1),
	//	logCtx.ContainerID, logCtx.ImageName(), logCtx.ImageFullID())
	tag := fmt.Sprintf(TAG_FORMAT, logCtx.ContainerID, logCtx.ImageFullID())

	log.Infof("Creating a new paper trail log shipper for url: %s", paperTrailURL)

	paperTrailClient, err := papertrail_go.NewLogger(context.Background(), paperTrailProto, paperTrailURL,
		tag, dbLocation, retention, workerCount, maxDiskUsage)
	if err != nil {
		err = errors.Wrapf(err, "Unable to create Paper trail client")
		log.Error(err)
		return nil, err
	}

	p := &paperTrailLogShipper{
		paperTrailClient: paperTrailClient,
	}

	return p, nil
}

func (p *paperTrailLogShipper) Name() string {
	return name
}

func (p *paperTrailLogShipper) Log(msg *logger.Message) error {
	if len(msg.Line) > 0 {
		err := p.paperTrailClient.Log(string(msg.Line))
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Unable to store the log for further processing: %s", msg.Line))
			log.Error(err)
			return err
		}
	}
	return nil
}

func (p *paperTrailLogShipper) Close() error {
	if p.paperTrailClient != nil {
		err := p.paperTrailClient.Close()
		if err != nil {
			err = errors.Wrapf(err, "Error while closing paperTrail client")
			log.Error(err)
			return err
		}
	}
	return nil
}
