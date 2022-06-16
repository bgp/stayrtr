package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bgp/stayrtr/cache"
	rtr "github.com/bgp/stayrtr/lib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	ENV_SSH_PASSWORD = "RTR_SSH_PASSWORD"
	ENV_SSH_KEY      = "RTR_SSH_KEY"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY
)

type thresholds []int64

var (
	version    = ""
	buildinfos = ""
	AppVersion = "RTRmon " + version + " " + buildinfos

	OneOff      = flag.Bool("oneoff", false, "dump as json and exits")
	Addr        = flag.String("addr", ":9866", "Server address")
	MetricsPath = flag.String("metrics", "/metrics", "Metrics path")
	OutFile     = flag.String("file", "diff.json", "Diff file (or URL path without /)")

	UserAgent                  = flag.String("useragent", fmt.Sprintf("StayRTR-%v (+https://github.com/bgp/stayrtr)", AppVersion), "User-Agent header")
	DisableConditionalRequests = flag.Bool("disable.conditional.requests", false, "Disable conditional requests (using If-None-Match/If-Modified-Since headers)")

	PrimaryHost            = flag.String("primary.host", "tcp://rtr.rpki.cloudflare.com:8282", "primary server")
	PrimaryValidateCert    = flag.Bool("primary.tls.validate", true, "Validate TLS")
	PrimaryValidateSSH     = flag.Bool("primary.ssh.validate", false, "Validate SSH key")
	PrimarySSHServerKey    = flag.String("primary.ssh.validate.key", "", "SSH server key SHA256 to validate")
	PrimarySSHAuth         = flag.String("primary.ssh.method", "none", "Select SSH method (none, password or key)")
	PrimarySSHAuthUser     = flag.String("primary.ssh.auth.user", "rpki", "SSH user")
	PrimarySSHAuthPassword = flag.String("primary.ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %s_1)", ENV_SSH_PASSWORD))
	PrimarySSHAuthKey      = flag.String("primary.ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %s_1)", ENV_SSH_KEY))
	PrimaryRefresh         = flag.Duration("primary.refresh", time.Second*600, "Refresh interval")
	PrimaryRTRBreak        = flag.Bool("primary.rtr.break", false, "Break RTR session at each interval")

	SecondaryHost            = flag.String("secondary.host", "https://rpki.cloudflare.com/rpki.json", "secondary server")
	SecondaryValidateCert    = flag.Bool("secondary.tls.validate", true, "Validate TLS")
	SecondaryValidateSSH     = flag.Bool("secondary.ssh.validate", false, "Validate SSH key")
	SecondarySSHServerKey    = flag.String("secondary.ssh.validate.key", "", "SSH server key SHA256 to validate")
	SecondarySSHAuth         = flag.String("secondary.ssh.method", "none", "Select SSH method (none, password or key)")
	SecondarySSHAuthUser     = flag.String("secondary.ssh.auth.user", "rpki", "SSH user")
	SecondarySSHAuthPassword = flag.String("secondary.ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %s_2)", ENV_SSH_PASSWORD))
	SecondarySSHAuthKey      = flag.String("secondary.ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %s_2)", ENV_SSH_KEY))
	SecondaryRefresh         = flag.Duration("secondary.refresh", time.Second*600, "Refresh interval")
	SecondaryRTRBreak        = flag.Bool("secondary.rtr.break", false, "Break RTR session at each interval")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")

	typeToId = map[string]int{
		"tcp": rtr.TYPE_PLAIN,
		"tls": rtr.TYPE_TLS,
		"ssh": rtr.TYPE_SSH,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		"key":      METHOD_KEY,
	}

	VRPCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_vrps",
			Help: "Total number of current VRPS in primary/secondary and current difference between primary and secondary.",
		},
		[]string{"server", "url", "type"},
	)
	VRPDifferenceForDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vrp_diff",
			Help: "Number of VRPS in [lhs_url] that are not in [rhs_url] that were first seen [visibility_seconds] ago in lhs.",
		},
		[]string{"lhs_url", "rhs_url", "visibility_seconds"},
	)
	RTRState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_state",
			Help: "State of the RTR session (up/down).",
		},
		[]string{"server", "url"},
	)
	RTRSerial = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_serial",
			Help: "Serial of the RTR session.",
		},
		[]string{"server", "url"},
	)
	RTRSession = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_session",
			Help: "ID of the RTR session.",
		},
		[]string{"server", "url"},
	)
	LastUpdate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "update",
			Help: "Timestamp of last update.",
		},
		[]string{"server", "url"},
	)

	idToInfo = map[int]string{
		0: "unknown",
		1: "primary",
		2: "secondary",
	}

	visibilityThresholds = thresholds{0, 56, 256, 596, 851, 1024, 1706, 3411}
)

func init() {
	prometheus.MustRegister(VRPCount)
	prometheus.MustRegister(VRPDifferenceForDuration)
	prometheus.MustRegister(RTRState)
	prometheus.MustRegister(RTRSerial)
	prometheus.MustRegister(RTRSession)
	prometheus.MustRegister(LastUpdate)

	flag.Var(&visibilityThresholds, "visibility.thresholds", "comma-separated list of visibility thresholds to override the default")
}

// String formats an array of thresholds as a comma separated string.
func (t *thresholds) String() string {
	res := []byte("")
	for idx, tr := range *t {
		res = strconv.AppendInt(res, tr, 10)
		if idx < len(*t)-1 {
			res = append(res, ","...)
		}
	}
	return string(res)
}

func (t *thresholds) Set(value string) error {
	// Setting overrides current values
	if len(*t) > 0 {
		*t = thresholds{}
	}

	for _, tr := range strings.Split(value, ",") {
		threshold, err := strconv.ParseInt(tr, 10, 32)

		if err != nil {
			return err
		}

		*t = append(*t, threshold)
	}

	return nil
}

func decodeJSON(data []byte) (*cache.VRPList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var vrplistjson cache.VRPList
	err := dec.Decode(&vrplistjson)
	return &vrplistjson, err
}

type Client struct {
	ValidateSSH     bool
	ValidateCert    bool
	SSHAuthUser     string
	SSHServerKey    string
	SSHAuthPassword string
	BreakRTR        bool
	authType        int
	keyBytes        []byte

	serial    uint32
	sessionID uint16

	FetchConfig *cache.FetchConfig

	Path            string
	RefreshInterval time.Duration

	qrtr chan bool

	lastUpdate time.Time

	compLock    *sync.RWMutex
	vrps        map[string]*VRPJsonSimple
	compRtrLock *sync.RWMutex
	vrpsRtr     map[string]*VRPJsonSimple

	unlock chan bool
	ch     chan int
	id     int

	rtrRefresh uint32
	rtrRetry   uint32
	rtrExpire  uint32
}

func NewClient() *Client {
	return &Client{
		compLock:    &sync.RWMutex{},
		vrps:        make(map[string]*VRPJsonSimple),
		compRtrLock: &sync.RWMutex{},
		vrpsRtr:     make(map[string]*VRPJsonSimple),
	}
}

func (c *Client) Start(id int, ch chan int) {
	c.ch = ch
	c.id = id

	pathUrl, err := url.Parse(c.Path)
	if err != nil {
		log.Fatal(err)
	}

	connType := pathUrl.Scheme
	rtrAddr := fmt.Sprintf("%s", pathUrl.Host)

	bypass := true
	for {

		if !bypass {
			select {
			case <-time.After(c.RefreshInterval):
			}
		}
		bypass = false

		if connType == "ssh" || connType == "tcp" || connType == "tls" {

			cc := rtr.ClientConfiguration{
				ProtocolVersion: rtr.PROTOCOL_VERSION_1,
				Log:             log.StandardLogger(),
			}

			clientSession := rtr.NewClientSession(cc, c)

			configTLS := &tls.Config{
				InsecureSkipVerify: !c.ValidateCert,
			}
			configSSH := &ssh.ClientConfig{
				Auth: make([]ssh.AuthMethod, 0),
				User: c.SSHAuthUser,
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					serverKeyHash := ssh.FingerprintSHA256(key)
					if c.ValidateSSH {
						if serverKeyHash != fmt.Sprintf("SHA256:%v", c.SSHServerKey) {
							return errors.New(fmt.Sprintf("Server key hash %v is different than expected key hash SHA256:%v", serverKeyHash, c.SSHServerKey))
						}
					}
					log.Infof("%d: Connected to server %v via ssh. Fingerprint: %v", id, remote.String(), serverKeyHash)
					return nil
				},
			}
			if c.authType == METHOD_PASSWORD {
				password := c.SSHAuthPassword
				configSSH.Auth = append(configSSH.Auth, ssh.Password(password))
			} else if c.authType == METHOD_KEY {
				signer, err := ssh.ParsePrivateKey(c.keyBytes)
				if err != nil {
					log.Fatal(err)
				}
				configSSH.Auth = append(configSSH.Auth, ssh.PublicKeys(signer))
			}

			log.Infof("%d: Connecting with %v to %v", id, connType, rtrAddr)

			c.qrtr = make(chan bool)
			c.unlock = make(chan bool)
			if !c.BreakRTR {
				go c.continuousRTR(clientSession)
			}

			err := clientSession.Start(rtrAddr, typeToId[connType], configTLS, configSSH)
			if err != nil {
				log.Fatal(err)
			}

			select {
			case <-c.qrtr:
				log.Infof("%d: Quitting RTR session", id)
			}
		} else {
			log.Infof("%d: Fetching %s", c.id, c.Path)
			data, _, _, err := c.FetchConfig.FetchFile(c.Path)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Debug(data)
			decoded, err := decodeJSON(data)
			if err != nil {
				log.Error(err)
				continue
			}

			c.lastUpdate = time.Now().UTC()
			tCurrentUpdate := time.Now().UTC().Unix()

			tmpVrpMap := make(map[string]*VRPJsonSimple)
			for _, vrp := range decoded.Data {
				asn, err := vrp.GetASN2()
				if err != nil {
					log.Errorf("%d: exploration error for %v asn: %v", id, vrp, err)
					continue
				}
				prefix, err := vrp.GetPrefix2()
				if err != nil {
					log.Errorf("%d: exploration error for %v prefix: %v", id, vrp, err)
					continue
				}

				maxlen := vrp.GetMaxLen()
				key := fmt.Sprintf("%s-%d-%d", prefix.String(), maxlen, asn)

				firstSeen := tCurrentUpdate
				currentEntry, ok := c.vrps[key]
				if ok {
					firstSeen = currentEntry.FirstSeen
				}

				vrpSimple := VRPJsonSimple{
					Prefix:    prefix.String(),
					ASN:       asn,
					Length:    uint8(maxlen),
					FirstSeen: firstSeen,
				}
				tmpVrpMap[key] = &vrpSimple
			}
			c.compLock.Lock()
			c.vrps = tmpVrpMap
			c.lastUpdate = time.Now().UTC()
			c.compLock.Unlock()
			if ch != nil {
				ch <- id
			}
		}

	}

}

func (c *Client) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu := pdu.(type) {
	case *rtr.PDUIPv4Prefix:
		vrp := VRPJsonSimple{
			Prefix:    pdu.Prefix.String(),
			ASN:       pdu.ASN,
			Length:    pdu.MaxLen,
			FirstSeen: time.Now().Unix(),
		}

		key := fmt.Sprintf("%s-%d-%d", pdu.Prefix.String(), pdu.MaxLen, pdu.ASN)
		c.compRtrLock.Lock()

		if pdu.Flags == rtr.FLAG_ADDED {
			c.vrpsRtr[key] = &vrp
		} else {
			delete(c.vrpsRtr, key)
		}

		c.compRtrLock.Unlock()
	case *rtr.PDUIPv6Prefix:
		vrp := VRPJsonSimple{
			Prefix:    pdu.Prefix.String(),
			ASN:       pdu.ASN,
			Length:    pdu.MaxLen,
			FirstSeen: time.Now().Unix(),
		}

		key := fmt.Sprintf("%s-%d-%d", pdu.Prefix.String(), pdu.MaxLen, pdu.ASN)
		c.compRtrLock.Lock()

		if pdu.Flags == rtr.FLAG_ADDED {
			c.vrpsRtr[key] = &vrp
		} else {
			delete(c.vrpsRtr, key)
		}

		c.compRtrLock.Unlock()
	case *rtr.PDUEndOfData:
		log.Infof("%d: Received: %v", c.id, pdu)

		c.compRtrLock.Lock()
		c.serial = pdu.SerialNumber
		tmpVrpMap := make(map[string]*VRPJsonSimple, len(c.vrpsRtr))
		for key, vrp := range c.vrpsRtr {
			tmpVrpMap[key] = vrp
		}
		c.compRtrLock.Unlock()

		c.compLock.Lock()
		c.vrps = tmpVrpMap

		c.rtrRefresh = pdu.RefreshInterval
		c.rtrRetry = pdu.RetryInterval
		c.rtrExpire = pdu.ExpireInterval
		c.lastUpdate = time.Now().UTC()
		c.compLock.Unlock()

		if c.ch != nil {
			c.ch <- c.id
		}

		if c.BreakRTR {
			cs.Disconnect()
		}
	case *rtr.PDUCacheResponse:
		log.Infof("%d: Received: %v", c.id, pdu)
		c.sessionID = pdu.SessionId
	case *rtr.PDUCacheReset:
		log.Infof("%d: Received: %v", c.id, pdu)
	case *rtr.PDUSerialNotify:
		log.Infof("%d: Received: %v", c.id, pdu)
	default:
		log.Infof("%d: Received: %v", c.id, pdu)
		cs.Disconnect()
	}
}

func (c *Client) ClientConnected(cs *rtr.ClientSession) {
	close(c.unlock)
	cs.SendResetQuery()

	RTRState.With(
		prometheus.Labels{
			"server": idToInfo[c.id],
			"url":    c.Path,
		}).Set(float64(1))
}

func (c *Client) ClientDisconnected(cs *rtr.ClientSession) {
	log.Warnf("%d: RTR client disconnected", c.id)
	select {
	case <-c.qrtr:
	default:
		close(c.qrtr)
	}

	RTRState.With(
		prometheus.Labels{
			"server": idToInfo[c.id],
			"url":    c.Path,
		}).Set(float64(0))
}

func (c *Client) continuousRTR(cs *rtr.ClientSession) {
	log.Debugf("%d: RTR routine started", c.id)
	var stop bool

	select {
	case <-c.unlock:
	case <-c.qrtr:
		stop = true
	}

	for !stop {
		select {
		case <-c.qrtr:
			stop = true
		case <-time.After(c.RefreshInterval):
			cs.SendSerialQuery(c.sessionID, c.serial)
		}
	}
}

func (c *Client) GetData() (map[string]*VRPJsonSimple, *diffMetadata) {
	c.compLock.RLock()
	defer c.compLock.RUnlock()
	vrps := c.vrps

	md := &diffMetadata{
		URL:       c.Path,
		Serial:    c.serial,
		SessionID: c.sessionID,
		Count:     len(vrps),

		RTRRefresh: c.rtrRefresh,
		RTRRetry:   c.rtrRetry,
		RTRExpire:  c.rtrExpire,

		LastFetch: c.lastUpdate.UnixNano() / 1e9,
	}

	return vrps, md
}

type Comparator struct {
	PrimaryClient, SecondaryClient *Client

	q    chan bool
	comp chan int

	OneOff bool

	diffLock         *sync.RWMutex
	onlyIn1, onlyIn2 []*VRPJsonSimple
	md1              *diffMetadata
	md2              *diffMetadata
}

func NewComparator(c1, c2 *Client) *Comparator {
	return &Comparator{
		PrimaryClient:   c1,
		SecondaryClient: c2,

		q:    make(chan bool),
		comp: make(chan int),

		diffLock: &sync.RWMutex{},
	}
}

func countFirstSeenOnOrBefore(vrps []*VRPJsonSimple, thresholdTimestamp int64) float64 {
	count := 0

	for _, vrp := range vrps {
		if vrp.FirstSeen <= thresholdTimestamp {
			count++
		}
	}

	return float64(count)
}

func Diff(a, b map[string]*VRPJsonSimple) []*VRPJsonSimple {
	onlyInA := make([]*VRPJsonSimple, 0)
	for key, vrp := range a {
		if _, ok := b[key]; !ok {
			onlyInA = append(onlyInA, vrp)
		}
	}
	return onlyInA
}

type diffMetadata struct {
	LastFetch int64  `json:"last-fetch"`
	URL       string `json:"url"`
	Serial    uint32 `json:"serial"`
	SessionID uint16 `json:"session-id"`
	Count     int    `json:"count"`

	RTRRefresh uint32 `json:"rtr-refresh"`
	RTRRetry   uint32 `json:"rtr-retry"`
	RTRExpire  uint32 `json:"rtr-expire"`
}

type VRPJsonSimple struct {
	ASN       uint32 `json:"asn"`
	Length    uint8  `json:"max-length"`
	Prefix    string `json:"prefix"`
	FirstSeen int64  `json:"first-seen"`
}

type diffExport struct {
	MetadataPrimary   *diffMetadata    `json:"metadata-primary"`
	MetadataSecondary *diffMetadata    `json:"metadata-secondary"`
	OnlyInPrimary     []*VRPJsonSimple `json:"only-primary"`
	OnlyInSecondary   []*VRPJsonSimple `json:"only-secondary"`
}

func (c *Comparator) ServeDiff(wr http.ResponseWriter, req *http.Request) {
	enc := json.NewEncoder(wr)

	c.diffLock.RLock()
	d1 := c.onlyIn1
	d2 := c.onlyIn2

	md1 := c.md1
	md2 := c.md2
	c.diffLock.RUnlock()
	export := diffExport{
		MetadataPrimary:   md1,
		MetadataSecondary: md2,
		OnlyInPrimary:     d1,
		OnlyInSecondary:   d2,
	}

	wr.Header().Add("content-type", "application/json")

	enc.Encode(export)
}

func (c *Comparator) Compare() {
	var donePrimary, doneSecondary bool
	var stop bool
	startedAt := time.Now().Unix()
	for !stop {
		select {
		case <-c.q:
			stop = true
			continue
		case id := <-c.comp:
			log.Infof("Worker %d finished: comparison", id)

			vrps1, md1 := c.PrimaryClient.GetData()
			vrps2, md2 := c.SecondaryClient.GetData()

			onlyIn1 := Diff(vrps1, vrps2)
			onlyIn2 := Diff(vrps2, vrps1)

			c.diffLock.Lock()
			c.onlyIn1 = onlyIn1
			c.onlyIn2 = onlyIn2

			c.md1 = md1
			c.md2 = md2

			VRPCount.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
					"type":   "total",
				}).Set(float64(len(vrps1)))

			VRPCount.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
					"type":   "diff",
				}).Set(float64(len(onlyIn1)))

			VRPCount.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
					"type":   "total",
				}).Set(float64(len(vrps2)))

			VRPCount.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
					"type":   "diff",
				}).Set(float64(len(onlyIn2)))

			for _, visibleFor := range visibilityThresholds {
				thresholdTimestamp := time.Now().Unix() - visibleFor
				// Prevent differences with value 0 appearing if the process has not
				// been running long enough for them to exist.
				if thresholdTimestamp >= startedAt {
					VRPDifferenceForDuration.With(
						prometheus.Labels{
							"lhs_url":            md1.URL,
							"rhs_url":            md2.URL,
							"visibility_seconds": strconv.FormatInt(visibleFor, 10),
						}).Set(countFirstSeenOnOrBefore(onlyIn1, thresholdTimestamp))

					VRPDifferenceForDuration.With(
						prometheus.Labels{
							"lhs_url":            md2.URL,
							"rhs_url":            md1.URL,
							"visibility_seconds": strconv.FormatInt(visibleFor, 10),
						}).Set(countFirstSeenOnOrBefore(onlyIn2, thresholdTimestamp))
				}
			}

			RTRSerial.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
				}).Set(float64(md1.Serial))

			RTRSerial.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
				}).Set(float64(md2.Serial))

			RTRSession.With(
				prometheus.Labels{
					"server": "primary",
					"url":    md1.URL,
				}).Set(float64(md1.SessionID))

			RTRSession.With(
				prometheus.Labels{
					"server": "secondary",
					"url":    md2.URL,
				}).Set(float64(md2.SessionID))

			c.diffLock.Unlock()

			if id == 1 {
				donePrimary = true

				LastUpdate.With(
					prometheus.Labels{
						"server": "primary",
						"url":    md1.URL,
					}).Set(float64(md1.LastFetch))

			} else if id == 2 {
				doneSecondary = true

				LastUpdate.With(
					prometheus.Labels{
						"server": "secondary",
						"url":    md2.URL,
					}).Set(float64(md2.LastFetch))
			}

			if c.OneOff && donePrimary && doneSecondary {
				// save file (one-off)
				stop = true
			}

		}
	}
}

func (c *Comparator) Start() error {
	if c.PrimaryClient == nil || c.SecondaryClient == nil {
		return errors.New("must have two clients")
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.PrimaryClient.Start(1, c.comp)
	}()
	go func() {
		defer wg.Done()
		c.SecondaryClient.Start(2, c.comp)
	}()

	go c.Compare()

	wg.Wait()
	close(c.q)
	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Printf("%s: illegal positional argument(s) provided (\"%s\") - did you mean to provide a flag?\n", os.Args[0], strings.Join(flag.Args(), " "))
		os.Exit(2)
	}
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	fc := cache.NewFetchConfig()
	fc.EnableEtags = !*DisableConditionalRequests
	fc.EnableLastModified = !*DisableConditionalRequests
	fc.UserAgent = *UserAgent

	c1 := NewClient()
	var ok bool
	c1.authType, ok = authToId[*PrimarySSHAuth]
	if !ok {
		log.Fatalf("Auth type %v unknown", *PrimarySSHAuth)
	}

	c1.SSHAuthUser = *PrimarySSHAuthUser
	c1.SSHAuthPassword = *PrimarySSHAuthPassword
	c1.Path = *PrimaryHost
	c1.RefreshInterval = *PrimaryRefresh
	c1.FetchConfig = fc
	c1.BreakRTR = *PrimaryRTRBreak

	if c1.SSHAuthPassword == "" {
		c1.SSHAuthPassword = os.Getenv(fmt.Sprintf("%s_1", ENV_SSH_PASSWORD))
	}

	if c1.authType == METHOD_KEY {
		var keyBytes []byte
		var err error
		if *PrimarySSHAuthKey == "" {
			keyBytesStr := os.Getenv(fmt.Sprintf("%s_1", ENV_SSH_KEY))
			keyBytes = []byte(keyBytesStr)
		} else {
			keyBytes, err = os.ReadFile(*PrimarySSHAuthKey)
			if err != nil {
				log.Fatal(err)
			}
		}
		c1.keyBytes = keyBytes
	}

	c2 := NewClient()
	c2.authType, ok = authToId[*SecondarySSHAuth]
	if !ok {
		log.Fatalf("Auth type %v unknown", *SecondarySSHAuth)
	}

	c2.SSHAuthUser = *SecondarySSHAuthUser
	c2.SSHAuthPassword = *SecondarySSHAuthPassword
	c2.Path = *SecondaryHost
	c2.RefreshInterval = *SecondaryRefresh
	c2.FetchConfig = fc
	c2.BreakRTR = *SecondaryRTRBreak

	if method, ok := authToId[*SecondarySSHAuth]; ok && method == METHOD_KEY {
		c2.SSHAuthPassword = os.Getenv(fmt.Sprintf("%s_2", ENV_SSH_PASSWORD))
	}

	if c2.authType == METHOD_KEY {
		var keyBytes []byte
		var err error
		if *SecondarySSHAuthKey == "" {
			keyBytesStr := os.Getenv(fmt.Sprintf("%s_2", ENV_SSH_KEY))
			keyBytes = []byte(keyBytesStr)
		} else {
			keyBytes, err = os.ReadFile(*SecondarySSHAuthKey)
			if err != nil {
				log.Fatal(err)
			}
		}
		c2.keyBytes = keyBytes
	}

	cmp := NewComparator(c1, c2)

	go func() {
		http.HandleFunc(fmt.Sprintf("/%s", *OutFile), cmp.ServeDiff)
		http.Handle(*MetricsPath, promhttp.Handler())

		log.Fatal(http.ListenAndServe(*Addr, nil))
	}()

	log.Fatal(cmp.Start())

}
