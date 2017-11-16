package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
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

	readers map[*logger.LogWatcher]struct{} // stores the active log followers
	mu      sync.Mutex
}

// rsyslog uses appname part of syslog message to fill in an %syslogtag% template
// attribute in rsyslog.conf. In order to be backward compatible to rfc3164
// tag will be also used as an appname
func rfc5424formatterWithAppNameAsTag(p syslog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format(time.RFC3339)
	pid := os.Getpid()
	msg := fmt.Sprintf("<%d>%d %s %s %s %d %s - %s",
		p, 1, timestamp, hostname, tag, pid, tag, content)
	return msg
}

// The timestamp field in rfc5424 is derived from rfc3339. Whereas rfc3339 makes allowances
// for multiple syntaxes, there are further restrictions in rfc5424, i.e., the maximum
// resolution is limited to "TIME-SECFRAC" which is 6 (microsecond resolution)
func rfc5424microformatterWithAppNameAsTag(p syslog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.999999Z07:00")
	pid := os.Getpid()
	msg := fmt.Sprintf("<%d>%d %s %s %s %d %s - %s",
		p, 1, timestamp, hostname, tag, pid, tag, content)
	return msg
}

//func parseLogFormat(logFormat string) (syslog.Formatter, syslog.Framer, error) {
//	switch logFormat {
//	case "":
//		return syslog.UnixFormatter, syslog.DefaultFramer, nil
//	case "rfc3164":
//		return syslog.RFC3164Formatter, syslog.DefaultFramer, nil
//	case "rfc5424":
//		//if proto == secureProto {
//		//	return rfc5424formatterWithAppNameAsTag, syslog.RFC5425MessageLengthFramer, nil
//		//}
//		return rfc5424formatterWithAppNameAsTag, syslog.DefaultFramer, nil
//	case "rfc5424micro":
//		//if proto == secureProto {
//		//	return rfc5424microformatterWithAppNameAsTag, syslog.RFC5425MessageLengthFramer, nil
//		//}
//		return rfc5424microformatterWithAppNameAsTag, syslog.DefaultFramer, nil
//	default:
//		return nil, nil, errors.New("Invalid papertrail log format")
//	}
//
//}

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

	//hostname, err := os.Hostname()
	//if err != nil {
	//	e := errors.Wrap(err, "failed to get the hostname")
	//	log.Error(e)
	//	return nil, e
	//}

	//logFormatter, logFramer, err := parseLogFormat(logCtx.Config["papertrail-log-format"])
	//if err != nil {
	//	return nil, err
	//}

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

	log.Infof("Creating a new paper trail logger for url: %s and token: %s", paperTrailURL, paperTrailToken)

	//writer, err := syslog.Dial("udp", paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, logCtx.ContainerID)
	//if err != nil {
	//	e := errors.Wrap(err, "failed to dial syslog")
	//	log.Error(e)
	//	return nil, e
	//}
	//
	////writer.SetFormatter(logFormatter)
	////writer.SetFramer(logFramer)

	return &PaperTrailLogger{
		paperTrailURL: paperTrailURL,
		token:         paperTrailToken,
		httpClient:    client,

		containerID:          logCtx.ContainerID,
		containerCreatedTime: logCtx.ContainerCreated,
		//writer:      writer,

		readers: map[*logger.LogWatcher]struct{}{},
	}, nil
}

func (p *PaperTrailLogger) Log(msg *logger.Message) error {
	//var err error

	//data, err := json.Marshal(msg)
	//if err != nil {
	//	e := errors.Wrap(err, "failed to marshal log msg")
	//	log.Error(e)
	//	return e
	//}
	//log.Infof("Marshaled msg: %s", string(data))
	if len(msg.Line) > 0 {
		writer, err := syslog.Dial("udp", p.paperTrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, p.containerID)
		if err != nil {
			e := errors.Wrap(err, "failed to dial syslog")
			log.Error(e)
			return e
		}

		//log.Infof("Paper trail logger -> log msg: %s and isError: %t", string(msg.Line), (msg.Source == "stderr" || msg.Err != nil))
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

// READ LOG LOGIC

// package main

// import (
// 	"net"
// 	"net/http"
// 	"time"
// 	"log"
// 	"io/ioutil"
// 	"encoding/json"
// 	"strconv"
// )

// type PaperTrailResponse struct{
// 	MinID  string `json:"min_id"`
// 	MaxID  string `json:"max_id"`
// 	Events []PaperTrailEvent `json:"events"`
// 	ReachedBeginning bool   `json:"reached_beginning"`
// 	ReachedEnd bool   `json:"reached_end"`
// 	MinTimeAt        string `json:"min_time_at"`
// }

// type PaperTrailEvent struct {
// ID                string `json:"id"`
// SourceIP          string `json:"source_ip"`
// Program           string `json:"program"`
// Message           string `json:"message"`
// ReceivedAt        string `json:"received_at"`
// GeneratedAt       string `json:"generated_at"`
// DisplayReceivedAt string `json:"display_received_at"`
// SourceID          int    `json:"source_id"`
// SourceName        string `json:"source_name"`
// Hostname          string `json:"hostname"`
// Severity          string `json:"severity"`
// Facility          string `json:"facility"`
// }

// func main(){

// 	minID := ""
// 	maxID := ""
// 	reached_end := false
// 	reached_beginning := false
// 	limit := 10
// 	for minID == "" || (reached_end == false && reached_beginning == false && minID != maxID) {

// 		req, err := http.NewRequest("GET", "https://papertrailapp.com/api/v1/events/search.json", nil)
// 		if err != nil {
// 			log.Fatalf("Error 1: %v", err)
// 		}

// 		q := req.URL.Query()
// 		q.Add("system_id", "grangant-mb")
// 		q.Add("q", "myapp1")
// 		q.Add("tail", "false")
// 		q.Add("limit", strconv.Itoa(limit))
// 		if minID != "" {
// 			q.Add("max_id", minID)
// 		}
// 		req.URL.RawQuery = q.Encode()

// 		req.Header.Set("X-Papertrail-Token", "3usY2t96ZRtACypjcC2z")

// 		resp, err := client.Do(req)
// 		if err != nil {
// 			log.Fatalf("Error 2: %v", err)
// 		}

// 		defer resp.Body.Close()

// 		body, err := ioutil.ReadAll(resp.Body)
// 		if err != nil {
// 			log.Fatalf("Error 3: %v", err)
// 		}

// 		pResp := &PaperTrailResponse{}

// 		err = json.Unmarshal(body, pResp)
// 		if err != nil {
// 			log.Fatalf("Error 4: %v", err)
// 		}
// 		log.Printf("Parsed Value min id: %s, max id: %s, reached_beginning: %t, reached_end: %t", pResp.MinID, pResp.MaxID, pResp.ReachedBeginning, pResp.ReachedEnd)
// 		minID = pResp.MinID
// 		maxID = pResp.MaxID
// 		reached_beginning = pResp.ReachedBeginning
// 		reached_end = pResp.ReachedEnd
// 		time.Sleep(time.Second)
// 	}
// }
