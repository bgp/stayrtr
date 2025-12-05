package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/ossec"
	"github.com/bgp/stayrtr/prefixfile"
	"github.com/bgp/stayrtr/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	ENV_CACHE        = "STAYRTR_CACHE"
	ENV_SSH_PASSWORD = "STAYRTR_SSH_PASSWORD"
	ENV_SSH_KEY      = "STAYRTR_SSH_AUTHORIZEDKEYS"

	DEFAULT_CACHE = "https://console.rpki-client.org/rpki.json"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY

	USE_SERIAL_DISABLE = iota
	USE_SERIAL_START
	USE_SERIAL_FULL
)

var (
	AppVersion = "StayRTR " + rtr.APP_VERSION

	MetricsAddr = flag.String("metrics.addr", ":9847", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	ExportPath           = flag.String("export.path", "/rpki.json", "Export path")
	EnableUpdateEndpoint = flag.Bool("update.endpoint", false, "Enable HTTP endpoint that expedites the next fetch")

	RTRVersion     = flag.Int("protocol", 2, "RTR protocol version. Default is version 2 (RFC 8210bis)")
	RefreshRTR     = flag.Int("rtr.refresh", 3600, "Refresh interval")
	RetryRTR       = flag.Int("rtr.retry", 600, "Retry interval")
	ExpireRTR      = flag.Int("rtr.expire", 7200, "Expire interval")
	SendNotifs     = flag.Bool("notifications", true, "Send notifications to clients (disable with -notifications=false)")
	EnforceVersion = flag.Bool("enforce.version", false, "Disable version negotiation")
	DisableBGPSec  = flag.Bool("disable.bgpsec", false, "Disable sending out BGPSEC Router Keys")
	DisableASPA    = flag.Bool("disable.aspa", false, "Disable sending out ASPA objects")
	EnableNODELAY  = flag.Bool("enable.nodelay", false, "Force enable TCP NODELAY (Likely increases CPU)")

	Bind = flag.String("bind", ":8282", "Bind address")

	BindTLS = flag.String("tls.bind", "", "Bind address for TLS")
	TLSCert = flag.String("tls.cert", "", "Certificate path")
	TLSKey  = flag.String("tls.key", "", "Private key path")

	BindSSH = flag.String("ssh.bind", "", "Bind address for SSH")
	SSHKey  = flag.String("ssh.key", "private.pem", "SSH host key")

	SSHAuthEnablePassword = flag.Bool("ssh.method.password", false, "Enable password auth")
	SSHAuthUser           = flag.String("ssh.auth.user", "rpki", "SSH user")
	SSHAuthPassword       = flag.String("ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %v)", ENV_SSH_PASSWORD))

	SSHAuthEnableKey  = flag.Bool("ssh.method.key", false, "Enable key auth")
	SSHAuthKeysBypass = flag.Bool("ssh.auth.key.bypass", false, "Accept any SSH key")
	SSHAuthKeysList   = flag.String("ssh.auth.key.file", "", fmt.Sprintf("Authorized SSH key file (if blank, will use envvar %v", ENV_SSH_KEY))

	TimeCheck = flag.Bool("checktime", true, "Check if JSON file isn't stale (disable by passing -checktime=false)")

	CacheBin = flag.String("cache", DEFAULT_CACHE, fmt.Sprintf("URL of the Validated RPKI data in JSON format (if blank, will use envvar %v", ENV_CACHE))

	Etag            = flag.Bool("etag", true, "Control usage of Etag header (disable with -etag=false)")
	LastModified    = flag.Bool("last.modified", true, "Control usage of Last-Modified header (disable with -last.modified=false)")
	UserAgent       = flag.String("useragent", fmt.Sprintf("StayRTR-%v (+https://github.com/bgp/stayrtr)", AppVersion), "User-Agent header")
	Mime            = flag.String("mime", "application/json", "Accept setting format (some servers may prefer text/json)")
	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")
	MaxConn         = flag.Int("maxconn", 0, "Max simultaneous connections (0 to disable limit)")

	Slurm        = flag.String("slurm", "", "Slurm configuration file (filters and assertions)")
	SlurmRefresh = flag.Bool("slurm.refresh", true, "Refresh along the cache (disable with -slurm.refresh=false)")

	LogLevel   = flag.String("loglevel", "info", "Log level")
	LogVerbose = flag.Bool("log.verbose", true, "Additional debug logs (disable with -log.verbose=false)")
	Version    = flag.Bool("version", false, "Print version")

	NumberOfVRPs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_vrps",
			Help: "Number of VRPs by source and status.",
		},
		[]string{"ip_version", "filtered", "path"},
	)
	NumberOfObjects = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_objects",
			Help: "Number of RPKI objects (in cache) by type",
		},
		[]string{"type"},
	)
	LastRefresh = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_refresh",
			Help: "Last successful request for the given URL.",
		},
		[]string{"path"},
	)
	LastChange = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_change",
			Help: "Last change.",
		},
		[]string{"path"},
	)
	RefreshStatusCode = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "refresh_requests_total",
			Help: "Total number of HTTP requests by status code",
		},
		[]string{"path", "code"},
	)
	ClientsMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_clients",
			Help: "Number of clients connected.",
		},
		[]string{"bind"},
	)
	PDUsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rtr_pdus",
			Help: "PDU received.",
		},
		[]string{"type"},
	)
	CurrentSerial = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rtr_serial",
			Help: "Current serial.",
		},
	)

	protoverToLib = map[int]uint8{
		0: rtr.PROTOCOL_VERSION_0,
		1: rtr.PROTOCOL_VERSION_1,
		2: rtr.PROTOCOL_VERSION_2,
	}
)

func initMetrics() {
	prometheus.MustRegister(NumberOfObjects)
	prometheus.MustRegister(NumberOfVRPs)
	prometheus.MustRegister(LastChange)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(RefreshStatusCode)
	prometheus.MustRegister(ClientsMetric)
	prometheus.MustRegister(PDUsRecv)
	prometheus.MustRegister(CurrentSerial)
}

func serveHTTP(mux *http.ServeMux) {
	srv := &http.Server{
		Addr:    *MetricsAddr,
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}

// newSHA256 will return the sha256 sum of the byte slice
// The return will be converted form a [32]byte to []byte
func newSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func decodeJSON(data []byte) (*prefixfile.RPKIList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var rpkilistjson prefixfile.RPKIList
	err := dec.Decode(&rpkilistjson)
	return &rpkilistjson, err
}

func isValidPrefixLength(prefix netip.Prefix, maxLength uint8) bool {
	plen := prefix.Bits()
	max := prefix.Addr().BitLen()
	if plen == 0 || uint8(plen) > maxLength || maxLength > uint8(max) {
		log.Errorf("%s Maxlength wrong: %d - %d", prefix, plen, maxLength)
		return false
	}
	return true
}

// processData will take a slice of prefix.VRPJson and attempt to convert them to a slice of rtr.VRP.
// Will check the following:
// 1 - The prefix is a valid prefix
// 2 - The ASN is a valid ASN
// 3 - The MaxLength is valid
// Will return a deduped slice, as well as total VRPs, IPv4 VRPs, IPv6 VRPs, BGPsec Keys and ASPA records
func processData(vrplistjson []prefixfile.VRPJson,
	brklistjson []prefixfile.BgpSecKeyJson,
	aspajson []prefixfile.VAPJson) /*Export*/ ([]rtr.VRP, []rtr.BgpsecKey, []rtr.VAP, int, int) {
	filterDuplicates := make(map[string]struct{})

	// It may be tempting to change this to a simple time.Since() but that will
	// grab the current time every time it's invoked, time calls can be slow on
	// some platforms, so lets just get the unix time when we start and use that
	// to compare it all
	NowUnix := time.Now().Unix()

	var vrplist []rtr.VRP
	var brklist = make([]rtr.BgpsecKey, 0)
	var aspalist = make([]rtr.VAP, 0)
	var countv4 int
	var countv6 int

	for _, v := range vrplistjson {
		prefix, err := v.GetPrefix2()
		if err != nil {
			log.Error(err)
			continue
		}
		asn, err := v.GetASN2()
		if err != nil {
			log.Error(err)
			continue
		}

		if !isValidPrefixLength(prefix, v.Length) {
			continue
		}

		if v.Expires != nil {
			// Prevent stale VRPs from being considered
			// https://github.com/bgp/stayrtr/issues/15
			if NowUnix > *v.Expires {
				continue
			}
		}

		if prefix.Addr().Is4() {
			countv4++
		} else {
			countv6++
		}

		key := fmt.Sprintf("%s,%d,%d", prefix, asn, v.Length)
		_, exists := filterDuplicates[key]
		if exists {
			continue
		}
		filterDuplicates[key] = struct{}{}

		vrp := rtr.VRP{
			Prefix: prefix,
			ASN:    asn,
			MaxLen: v.Length,
		}
		vrplist = append(vrplist, vrp)
	}

	sort.Slice(vrplist, func(i, j int) bool {
		// Sort VRPs as per draft-ietf-sidrops-8210bis-10
		/*
			11. ROA PDU Race Minimization
				When a cache is sending ROA (IPv4 or IPv6) PDUs to a router, especially an initial
				full load in response to a Reset Query PDU, two undesirable race conditions are possible:

			Break Before Make:
				For some prefix P, an AS may announce two (or more) ROAs because they are in the
				process of changing what provider AS is announcing P. This is a case of "make before break."
				If a cache is feeding a router and sends the one not yet in service a significant time
				before sending the one currently in service, then BGP data could be marked invalid during
				the interval. To minimize that interval, the cache SHOULD announce all ROAs for the same
				prefix as close to sequentially as possible.
			Shorter Prefix First:
				If an AS has issued a ROA for P0, and another AS (likely their customer) has issued a ROA
				for P1 which is a sub-prefix of P0, a router which receives the ROA for P0 before that for
				P1 is likely to mark a BGP prefix P1 invalid. Therefore, the cache SHOULD announce the
				sub-prefix P1 before the covering prefix P0.
		*/

		if vrplist[i].Prefix.Bits() == vrplist[j].Prefix.Bits() {
			if vrplist[i].MaxLen != vrplist[j].MaxLen {
				return vrplist[i].MaxLen > vrplist[j].MaxLen
			}
			return vrplist[i].Prefix.Addr().Compare(vrplist[j].Prefix.Addr()) < 1
		} else {
			return vrplist[i].Prefix.Bits() > vrplist[j].Prefix.Bits()
		}
	})

	for _, v := range brklistjson {
		if v.Expires != nil {
			// Prevent stale VRPs from being considered
			// https://github.com/bgp/stayrtr/issues/15
			if NowUnix > *v.Expires {
				continue
			}
		}

		SKIBytes, err := hex.DecodeString(v.Ski)
		if err != nil {
			continue
		}

		brklist = append(brklist, rtr.BgpsecKey{
			ASN:    v.Asn,
			Pubkey: v.Pubkey,
			Ski:    SKIBytes,
		})
	}

	for _, v := range aspajson {
		if v.Expires != nil {
			if NowUnix > *v.Expires {
				continue
			}
		}

		// Ensure that these are sorted, otherwise they
		// don't hash right.
		sort.Slice(v.Providers, func(i, j int) bool {
			return v.Providers[i] < v.Providers[j]
		})

		aspalist = append(aspalist, rtr.VAP{
			CustomerASN: v.CustomerAsid,
			Providers:   v.Providers,
		})
	}

	return vrplist, brklist, aspalist, countv4, countv6
}

type IdenticalFile struct {
	File string
}

func (e IdenticalFile) Error() string {
	return fmt.Sprintf("File %s is identical to the previous version", e.File)
}

var errRPKIJsonFileTooOld = errors.New("RPKI JSON file is older than 24 hours")

// Update the state based on the current slurm file and data.
func (s *state) updateFromNewState() error {
	vrpsjson := s.lastdata.ROA
	if vrpsjson == nil {
		return nil
	}
	bgpsecjson := s.lastdata.BgpSecKeys
	if bgpsecjson == nil {
		bgpsecjson = make([]prefixfile.BgpSecKeyJson, 0)
	}
	aspajson := s.lastdata.ASPA
	if aspajson == nil {
		aspajson = make([]prefixfile.VAPJson, 0)
	}

	buildtime, err := time.Parse(time.RFC3339, s.lastdata.Metadata.Buildtime)
	if s.lastdata.Metadata.GeneratedUnix != nil {
		buildtime, err = time.Unix(*s.lastdata.Metadata.GeneratedUnix, 0), nil
	}
	if s.checktime {
		if err != nil {
			return err
		}
		notafter := buildtime.Add(time.Hour * 24)
		if time.Now().UTC().After(notafter) {
			log.Warnf("RPKI JSON file is older than 24 hours: %v", buildtime)
			return errRPKIJsonFileTooOld
		}
	}

	if s.slurm != nil {
		vrpsjson, aspajson, bgpsecjson = s.slurm.FilterAssert(vrpsjson, aspajson, bgpsecjson, log.StandardLogger())
	}

	vrps, brks, vaps, countv4, countv6 := processData(vrpsjson, bgpsecjson, aspajson)
	count := len(vrps) + len(brks) + len(vaps)

	log.Infof("New update (%v uniques, %v total prefixes, %v vaps, %v router keys).", len(vrps), count, len(vaps), len(brks))
	return s.applyUpdateFromNewState(vrps, brks, vaps, vrpsjson, bgpsecjson, aspajson, countv4, countv6)
}

// Update the state based on the currently loaded files
func (s *state) reloadFromCurrentState() error {
	vrpsjson := s.lastdata.ROA
	if vrpsjson == nil {
		return nil
	}
	bgpsecjson := s.lastdata.BgpSecKeys
	if bgpsecjson == nil {
		bgpsecjson = make([]prefixfile.BgpSecKeyJson, 0)
	}
	aspajson := s.lastdata.ASPA
	if aspajson == nil {
		aspajson = make([]prefixfile.VAPJson, 0)
	}

	buildtime, err := time.Parse(time.RFC3339, s.lastdata.Metadata.Buildtime)
	if s.lastdata.Metadata.GeneratedUnix != nil {
		buildtime, err = time.Unix(*s.lastdata.Metadata.GeneratedUnix, 0), nil
	}
	if s.checktime {
		if err != nil {
			return err
		}
		notafter := buildtime.Add(time.Hour * 24)
		if time.Now().UTC().After(notafter) {
			log.Warnf("RPKI JSON file is older than 24 hours: %v", buildtime)
			return errRPKIJsonFileTooOld
		}
	}

	if s.slurm != nil {
		vrpsjson, aspajson, bgpsecjson = s.slurm.FilterAssert(vrpsjson, aspajson, bgpsecjson, log.StandardLogger())
	}

	vrps, brks, vaps, countv4, countv6 := processData(vrpsjson, bgpsecjson, aspajson)
	count := len(vrps) + len(brks) + len(vaps)
	if s.server.CountSDs() != count {
		log.Infof("New update to old state (%v uniques, %v total prefixes). (old %v - new %v)", len(vrps), count, s.server.CountSDs(), count)
		return s.applyUpdateFromNewState(vrps, brks, vaps, vrpsjson, bgpsecjson, aspajson, countv4, countv6)
	}
	return nil
}

func (s *state) applyUpdateFromNewState(vrps []rtr.VRP, brks []rtr.BgpsecKey, vaps []rtr.VAP,
	vrpsjson []prefixfile.VRPJson, brksjson []prefixfile.BgpSecKeyJson, aspajson []prefixfile.VAPJson,
	countv4 int, countv6 int) error {

	SDs := make([]rtr.SendableData, 0, len(vrps)+len(brks)+len(vaps))
	for _, v := range vrps {
		SDs = append(SDs, v.Copy())
	}
	for _, v := range brks {
		SDs = append(SDs, v.Copy())
	}
	for _, v := range vaps {
		SDs = append(SDs, v.Copy())
	}
	if !s.server.AddData(SDs) {
		log.Info("No difference to current cache")
		return nil
	}

	serial, _ := s.server.GetCurrentSerial()
	log.Infof("Update added, new serial %v", serial)
	if s.sendNotifs {
		log.Debugf("Sending notifications to clients")
		s.server.NotifyClientsLatest()
	}
	CurrentSerial.Set(float64(serial))

	s.lockJson.Lock()
	s.exported = prefixfile.RPKIList{
		Metadata: prefixfile.MetaData{
			Counts:    len(vrpsjson),
			Buildtime: s.lastdata.Metadata.Buildtime,
		},
		ROA:        vrpsjson,
		BgpSecKeys: brksjson,
		ASPA:       aspajson,
	}
	s.lockJson.Unlock()

	if s.metricsEvent != nil {
		var countv4_dup int
		var countv6_dup int
		for _, vrp := range vrps {
			if vrp.Prefix.Addr().Is4() {
				countv4_dup++
			} else if vrp.Prefix.Addr().Is6() {
				countv6_dup++
			}
		}
		s.metricsEvent.UpdateMetrics(countv4, countv6, countv4_dup, countv6_dup, s.lastchange, s.lastts, *CacheBin, len(brks), len(vaps))
	}

	return nil
}

func (s *state) updateFile(file string) (bool, error) {
	log.Debugf("Refreshing cache from %s", file)

	s.lastts = time.Now().UTC()
	data, code, lastrefresh, err := s.fetchConfig.FetchFile(file)
	if err != nil {
		return false, err
	}
	if lastrefresh {
		LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	hsum := newSHA256(data)
	if s.lasthashCache != nil {
		cres := bytes.Compare(s.lasthashCache, hsum)
		if cres == 0 {
			return false, IdenticalFile{File: file}
		}
	}

	log.Debugf("new cache file: Updating sha256 hash %x -> %x", s.lasthashCache, hsum)
	s.lasthashCache = hsum

	rpkilistjson, err := decodeJSON(data)
	if err != nil {
		return false, err
	}

	s.lastchange = time.Now().UTC()
	s.lastdata = rpkilistjson

	return true, nil
}

func (s *state) updateSlurm(file string) (bool, error) {
	log.Debugf("Refreshing slurm from %v", file)
	data, code, lastrefresh, err := s.fetchConfig.FetchFile(file)
	if err != nil {
		return false, err
	}
	if lastrefresh {
		LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	hsum := newSHA256(data)
	if s.lasthashSlurm != nil {
		cres := bytes.Compare(s.lasthashSlurm, hsum)
		if cres == 0 {
			return false, IdenticalFile{File: file}
		}
	}
	log.Debugf("new slurm file: Updating sha256 hash %x -> %x", s.lasthashCache, hsum)
	s.lasthashSlurm = hsum

	buf := bytes.NewBuffer(data)

	slurm, err := prefixfile.DecodeJSONSlurm(buf)
	if err != nil {
		return false, err
	}
	s.slurm = slurm
	return true, nil
}

func (s *state) updateDelay(delay *time.Ticker, interval int) {
	if s.lastchange.IsZero() {
		delay.Reset(30 * time.Second)
	} else {
		delay.Reset(time.Duration(interval) * time.Second)
	}
}

func (s *state) errRPKIJsonFileTooOldHandler() {
	// If the exiting build time is over 24 hours, It's time to drop everything out.
	// to avoid routing on stale data
	buildTime := s.exported.Metadata.GetBuildTime()
	if !buildTime.IsZero() && time.Since(buildTime) > time.Hour*24 {
		log.Errorf("Data is stale, clearing it all.")
		s.server.AddData([]rtr.SendableData{}) // empty the store of sendable stuff, triggering a emptying of the RTR server
	}
}

func (s *state) routineUpdate(file string, interval int, slurmFile string) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs, slurm: %v)", file, interval, slurmFile)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	delay := time.NewTicker(time.Duration(interval) * time.Second)
	initialSyncNotComplete := false
	for {
		if s.lastchange.IsZero() {
			log.Warn("Initial sync not complete. Refreshing every 30 seconds")
			delay.Reset(30 * time.Second)
			initialSyncNotComplete = true
		} else {
			if initialSyncNotComplete {
				delay.Reset(time.Duration(interval) * time.Second)
			}
		}
		select {
		case <-delay.C:
		case <-signals:
			log.Debug("Received HUP signal")
			s.updateDelay(delay, interval)
		case <-s.triggerUpdate:
			log.Debug("Received triggered update")
			s.updateDelay(delay, interval)
		}
		slurmNotPresentOrUpdated := false

		updateFileWG := sync.WaitGroup{}
		updateFileWG.Add(2)
		go func() {
			defer updateFileWG.Done()
			if slurmFile != "" {
				var err error
				slurmNotPresentOrUpdated, err = s.updateSlurm(slurmFile)
				if err != nil {
					switch err.(type) {
					case utils.HttpNotModified:
						log.Info(err)
					case utils.IdenticalEtag:
						log.Info(err)
					default:
						log.Errorf("Slurm: %v", err)
					}
				}
			}
		}()
		var cacheUpdated bool

		go func() {
			defer updateFileWG.Done()
			var err error
			cacheUpdated, err = s.updateFile(file)
			if err != nil {
				switch err.(type) {
				case utils.HttpNotModified:
					log.Info(err)
				case utils.IdenticalEtag:
					log.Info(err)
				case IdenticalFile:
					log.Info(err)
				default:
					log.Errorf("Error updating: %v", err)
				}
			}
		}()

		updateFileWG.Wait()

		// Only process the first time after there is either a cache or SLURM
		// update.
		if cacheUpdated || slurmNotPresentOrUpdated {
			err := s.updateFromNewState()
			if err != nil {
				log.Errorf("Error updating from new state: %v", err)
				if err == errRPKIJsonFileTooOld {
					s.errRPKIJsonFileTooOldHandler()
				}
			}
		} else {
			err := s.reloadFromCurrentState()
			if err != nil {
				log.Errorf("Error updating from current state: %v", err)
				if err == errRPKIJsonFileTooOld {
					s.errRPKIJsonFileTooOldHandler()
				}
			}
		}
	}
}

func (s *state) exporter(wr http.ResponseWriter, r *http.Request) {
	s.lockJson.RLock()
	toExport := s.exported
	s.lockJson.RUnlock()
	enc := json.NewEncoder(wr)
	enc.Encode(toExport)
}

func (s *state) updateNow(wr http.ResponseWriter, r *http.Request) {
	wr.Header().Set("Content-Type", "application/json")

	response := make(map[string]interface{})
	if s.TriggerUpdate() {
		response["status"] = "success"
		response["message"] = "Update triggered successfully"
		wr.WriteHeader(http.StatusOK)
	} else {
		response["status"] = "error"
		response["message"] = "Update not triggered. Queue is full or not ready"
		wr.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(wr).Encode(response)
}

func (s *state) TriggerUpdate() bool {
	select {
	case s.triggerUpdate <- struct{}{}:
		return true
	default:
		// Channel is full or not ready, log a warning
		log.Warn("Update trigger skipped: update ongoing or not ready")
		return false
	}
}

type state struct {
	lastdata      *prefixfile.RPKIList
	lasthashCache []byte
	lasthashSlurm []byte
	lastchange    time.Time
	lastts        time.Time
	sendNotifs    bool

	fetchConfig *utils.FetchConfig

	server *rtr.Server

	metricsEvent *metricsEvent

	exported prefixfile.RPKIList
	lockJson *sync.RWMutex

	slurm *prefixfile.SlurmConfig

	checktime bool

	triggerUpdate chan struct{}
}

type metricsEvent struct {
}

func (m *metricsEvent) ClientConnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Inc()
}

func (m *metricsEvent) ClientDisconnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Dec()
}

func (m *metricsEvent) HandlePDU(c *rtr.Client, pdu rtr.PDU) {
	PDUsRecv.WithLabelValues(
		strings.ToLower(
			strings.Replace(
				rtr.TypeToString(
					pdu.GetType()),
				" ",
				"_", -1))).Inc()
}

func (m *metricsEvent) UpdateMetrics(numIPv4 int, numIPv6 int, numIPv4filtered int, numIPv6filtered int, changed time.Time, refreshed time.Time, file string, brkCount int, aspaCount int) {
	NumberOfObjects.WithLabelValues("vaps").Set(float64(aspaCount))
	NumberOfObjects.WithLabelValues("bgpsec_pubkeys").Set(float64(brkCount))
	NumberOfObjects.WithLabelValues("vrps").Set(float64(numIPv4 + numIPv6))
	NumberOfObjects.WithLabelValues("effective_vrps").Set(float64(numIPv4filtered + numIPv6filtered))

	NumberOfVRPs.WithLabelValues("ipv4", "filtered", file).Set(float64(numIPv4filtered))
	NumberOfVRPs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(numIPv4))
	NumberOfVRPs.WithLabelValues("ipv6", "filtered", file).Set(float64(numIPv6filtered))
	NumberOfVRPs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(numIPv6))
	LastChange.WithLabelValues(file).Set(float64(changed.UnixNano() / 1e9))
}

func main() {
	err := ossec.PledgePromises("dns inet rpath stdio tty")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pledge failed: %v\n", err)
		os.Exit(1)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
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

	deh := &rtr.DefaultRTREventHandler{
		Log: log.StandardLogger(),
	}

	sc := rtr.ServerConfiguration{
		ProtocolVersion: protoverToLib[*RTRVersion],
		KeepDifference:  3,
		Log:             log.StandardLogger(),
		LogVerbose:      *LogVerbose,

		RefreshInterval: uint32(*RefreshRTR),
		RetryInterval:   uint32(*RetryRTR),
		ExpireInterval:  uint32(*ExpireRTR),

		EnforceVersion: *EnforceVersion,
		DisableBGPSec:  *DisableBGPSec,
		DisableASPA:    *DisableASPA,
		EnableNODELAY:  *EnableNODELAY,
	}

	var me *metricsEvent
	var enableHTTP bool
	if *MetricsAddr != "" {
		initMetrics()
		me = &metricsEvent{}
		enableHTTP = true
	}

	server := rtr.NewServer(sc, me, deh)
	deh.SetSDManager(server)

	s := state{
		server:       server,
		lastdata:     &prefixfile.RPKIList{},
		metricsEvent: me,
		sendNotifs:   *SendNotifs,
		checktime:    *TimeCheck,
		lockJson:     &sync.RWMutex{},

		fetchConfig: utils.NewFetchConfig(),

		triggerUpdate: make(chan struct{}, 1), // limit the number of queued updates. Downside: HTTP call to endpoint may fail
	}
	s.fetchConfig.UserAgent = *UserAgent
	s.fetchConfig.Mime = *Mime
	s.fetchConfig.EnableEtags = *Etag
	s.fetchConfig.EnableLastModified = *LastModified

	if *CacheBin == DEFAULT_CACHE && os.Getenv(ENV_CACHE) != "" {
		*CacheBin = os.Getenv(ENV_CACHE)
	}

	if enableHTTP {
		mux := http.NewServeMux()
		mux.Handle(*MetricsPath, promhttp.Handler())
		mux.HandleFunc("GET /clients", server.GetClientRemoteAddrs)

		if *ExportPath != "" {
			mux.HandleFunc(*ExportPath, s.exporter)
		}
		if *EnableUpdateEndpoint {
			mux.HandleFunc("/api/update", s.updateNow)
		}

		go serveHTTP(mux)
	}

	if *Bind == "" && *BindTLS == "" && *BindSSH == "" {
		log.Fatalf("Specify at least a bind address using -bind , -tls.bind , or -ssh.bind")
	}

	fileFetchWG := sync.WaitGroup{}
	fileFetchWG.Add(2)

	go func() {
		defer fileFetchWG.Done()
		_, err := s.updateFile(*CacheBin)
		if err != nil {
			switch err.(type) {
			case utils.HttpNotModified:
				log.Info(err)
			case IdenticalFile:
				log.Info(err)
			case utils.IdenticalEtag:
				log.Info(err)
			default:
				log.Errorf("Error updating: %v", err)
			}
		}
	}()

	slurmFile := *Slurm
	go func() {
		defer fileFetchWG.Done()
		if slurmFile != "" {
			_, err := s.updateSlurm(slurmFile)
			if err != nil {
				switch err.(type) {
				case utils.HttpNotModified:
					log.Info(err)
				case utils.IdenticalEtag:
					log.Info(err)
				default:
					log.Errorf("Slurm: %v", err)
				}
			}
			if !*SlurmRefresh {
				slurmFile = ""
			}
		}
	}()

	fileFetchWG.Wait()

	// Initial calculation of state (after fetching cache + slurm)
	err := s.updateFromNewState()
	if err != nil {
		log.Warnf("Error setting up initial state: %s", err)
	}

	if *Bind != "" {
		go func() {
			sessid := server.GetSessionId(protoverToLib[*RTRVersion])
			log.Infof("StayRTR Server started (sessionID:%d, refresh:%d, retry:%d, expire:%d)", sessid, sc.RefreshInterval, sc.RetryInterval, sc.ExpireInterval)
			log.Infof("StayRTR Server v%s binding to %s", rtr.APP_VERSION, *Bind)
			err := server.Start(*Bind)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	if *BindTLS != "" {
		cert, err := tls.LoadX509KeyPair(*TLSCert, *TLSKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		go func() {
			err := server.StartTLS(*BindTLS, &tlsConfig)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}
	if *BindSSH != "" {
		sshkey, err := os.ReadFile(*SSHKey)
		if err != nil {
			log.Fatal(err)
		}
		private, err := ssh.ParsePrivateKey(sshkey)
		if err != nil {
			log.Fatal("Failed to parse SSH private key: ", err)
		}

		sshConfig := ssh.ServerConfig{}

		log.Infof("Enabling ssh with the following authentications: password=%v, key=%v", *SSHAuthEnablePassword, *SSHAuthEnableKey)
		if *SSHAuthEnablePassword {
			password := *SSHAuthPassword
			if password == "" {
				password = os.Getenv(ENV_SSH_PASSWORD)
			}
			sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, suppliedPassword []byte) (*ssh.Permissions, error) {
				log.Infof("Connected (ssh-password): %v/%v", conn.User(), conn.RemoteAddr())
				if conn.User() != *SSHAuthUser || !bytes.Equal(suppliedPassword, []byte(password)) {
					log.Warnf("Wrong user or password for %v/%v. Disconnecting.", conn.User(), conn.RemoteAddr())
					return nil, errors.New("wrong user or password")
				}

				return &ssh.Permissions{
					CriticalOptions: make(map[string]string),
					Extensions:      make(map[string]string),
				}, nil
			}
		}
		if *SSHAuthEnableKey {
			var sshClientKeysToDecode string
			if *SSHAuthKeysList == "" {
				sshClientKeysToDecode = os.Getenv(ENV_SSH_KEY)
			} else {
				sshClientKeysToDecodeBytes, err := os.ReadFile(*SSHAuthKeysList)
				if err != nil {
					log.Fatal(err)
				}
				sshClientKeysToDecode = string(sshClientKeysToDecodeBytes)
			}
			sshClientKeys := strings.Split(sshClientKeysToDecode, "\n")

			sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				keyBase64 := base64.RawStdEncoding.EncodeToString(key.Marshal())
				if !*SSHAuthKeysBypass {
					var noKeys bool
					for i, k := range sshClientKeys {
						if k == "" {
							continue
						}
						if strings.HasPrefix(k, fmt.Sprintf("%v %v", key.Type(), keyBase64)) {
							log.Infof("Connected (ssh-key): %v/%v with key %v %v (matched with line %v)",
								conn.User(), conn.RemoteAddr(), key.Type(), keyBase64, i+1)
							noKeys = true
							break
						}
					}
					if !noKeys {
						log.Warnf("No key for %v/%v %v %v. Disconnecting.", conn.User(), conn.RemoteAddr(), key.Type(), keyBase64)
						return nil, errors.New("provided ssh key not found")
					}
				} else {
					log.Infof("Connected (ssh-key): %v/%v with key %v %v", conn.User(), conn.RemoteAddr(), key.Type(), keyBase64)
				}

				return &ssh.Permissions{
					CriticalOptions: make(map[string]string),
					Extensions:      make(map[string]string),
				}, nil
			}
		}

		if !(*SSHAuthEnableKey || *SSHAuthEnablePassword) {
			sshConfig.NoClientAuth = true
		}

		sshConfig.AddHostKey(private)
		go func() {
			err := server.StartSSH(*BindSSH, &sshConfig)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	s.routineUpdate(*CacheBin, *RefreshInterval, slurmFile)

	return nil
}
