package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/prefixfile"
	"github.com/bgp/stayrtr/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	ENV_SSH_PASSWORD = "STAYRTR_SSH_PASSWORD"
	ENV_SSH_KEY      = "STAYRTR_SSH_AUTHORIZEDKEYS"

	METHOD_NONE = iota
	METHOD_PASSWORD
	METHOD_KEY

	USE_SERIAL_DISABLE = iota
	USE_SERIAL_START
	USE_SERIAL_FULL
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "StayRTR " + version + " " + buildinfos

	MetricsAddr = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	ExportPath = flag.String("export.path", "/rpki.json", "Export path")

	RTRVersion = flag.Int("protocol", 1, "RTR protocol version")
	SessionID  = flag.Int("rtr.sessionid", -1, "Set session ID (if < 0: will be randomized)")
	RefreshRTR = flag.Int("rtr.refresh", 3600, "Refresh interval")
	RetryRTR   = flag.Int("rtr.retry", 600, "Retry interval")
	ExpireRTR  = flag.Int("rtr.expire", 7200, "Expire interval")

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

	CacheBin = flag.String("cache", "https://console.rpki-client.org/vrps.json", "URL of the cached JSON data")

	Etag            = flag.Bool("etag", true, "Control usage of Etag header (disable with -etag=false)")
	LastModified    = flag.Bool("last.modified", true, "Control usage of Last-Modified header (disable with -last.modified=false)")
	UserAgent       = flag.String("useragent", fmt.Sprintf("StayRTR-%v (+https://github.com/bgp/stayrtr)", AppVersion), "User-Agent header")
	Mime            = flag.String("mime", "application/json", "Accept setting format (some servers may prefer text/json)")
	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")
	MaxConn         = flag.Int("maxconn", 0, "Max simultaneous connections (0 to disable limit)")
	SendNotifs      = flag.Bool("notifications", true, "Send notifications to clients (disable with -notifications=false)")

	Slurm        = flag.String("slurm", "", "Slurm configuration file (filters and assertions)")
	SlurmRefresh = flag.Bool("slurm.refresh", true, "Refresh along the cache (disable with -slurm.refresh=false)")

	LogLevel   = flag.String("loglevel", "info", "Log level")
	LogVerbose = flag.Bool("log.verbose", true, "Additional debug logs (disable with -log.verbose=false)")
	Version    = flag.Bool("version", false, "Print version")

	NumberOfVRPs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_vrps",
			Help: "Number of VRPs.",
		},
		[]string{"ip_version", "filtered", "path"},
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

	protoverToLib = map[int]uint8{
		0: rtr.PROTOCOL_VERSION_0,
		1: rtr.PROTOCOL_VERSION_1,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		//"key":   METHOD_KEY,
	}
	serialToId = map[string]int{
		"disable": USE_SERIAL_DISABLE,
		"startup": USE_SERIAL_START,
		"full":    USE_SERIAL_FULL,
	}
)

func initMetrics() {
	prometheus.MustRegister(NumberOfVRPs)
	prometheus.MustRegister(LastChange)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(RefreshStatusCode)
	prometheus.MustRegister(ClientsMetric)
	prometheus.MustRegister(PDUsRecv)
}

func metricHTTP() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func checkFile(data []byte) ([]byte, error) {
	hsum := sha256.Sum256(data)
	return hsum[:], nil
}

func decodeJSON(data []byte) (*prefixfile.VRPList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var vrplistjson prefixfile.VRPList
	err := dec.Decode(&vrplistjson)
	return &vrplistjson, err
}

func checkPrefixLengths(prefix *net.IPNet, maxLength uint8) bool {
	plen, max := net.IPMask.Size(prefix.Mask)

	if uint8(plen) > maxLength || maxLength > uint8(max) {
		log.Errorf("%s Maxlength wrong: %d - %d", prefix, plen, maxLength)
		return false
	}
	return true
}

func processData(vrplistjson []prefixfile.VRPJson) ([]rtr.VRP, int, int, int) {
	filterDuplicates := make(map[string]bool)

	vrplist := make([]rtr.VRP, 0)

	var count int
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

		if !checkPrefixLengths(prefix, v.Length) {
			continue
		}

		if prefix.IP.To4() != nil {
			countv4++
		} else if prefix.IP.To16() != nil {
			countv6++
		}
		count++

		key := fmt.Sprintf("%s,%d,%d", prefix, asn, v.Length)
		_, exists := filterDuplicates[key]
		if !exists {
			filterDuplicates[key] = true
		} else {
			continue
		}

		vrp := rtr.VRP{
			Prefix: *prefix,
			ASN:    asn,
			MaxLen: v.Length,
		}
		vrplist = append(vrplist, vrp)
	}
	return vrplist, count, countv4, countv6
}

type IdenticalFile struct {
	File string
}

func (e IdenticalFile) Error() string {
	return fmt.Sprintf("File %s is identical to the previous version", e.File)
}

func (s *state) updateFile(file string) error {
	sessid, _ := s.server.GetSessionId(nil)

	log.Debugf("Refreshing cache from %s", file)

	s.lastts = time.Now().UTC()
	data, code, lastrefresh, err := s.fetchConfig.FetchFile(file)
	if err != nil {
		return err
	}
	if lastrefresh {
		LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	hsum, _ := checkFile(data)
	if s.lasthash != nil {
		cres := bytes.Compare(s.lasthash, hsum)
		if cres == 0 {
			return IdenticalFile{File: file}
		}
	}

	s.lastchange = time.Now().UTC()
	s.lastdata = data

	vrplistjson, err := decodeJSON(s.lastdata)
	if err != nil {
		return err
	}

	if s.checktime {
		buildtime, err := time.Parse(time.RFC3339, vrplistjson.Metadata.Buildtime)
		if err != nil {
			return err
		}
		notafter := buildtime.Add(time.Hour * 24)
		if time.Now().UTC().After(notafter) {
			return errors.New(fmt.Sprintf("VRP JSON file is older than 24 hours: %v", buildtime))
		}
	}

	vrpsjson := vrplistjson.Data
	if s.slurm != nil {
		kept, removed := s.slurm.FilterOnVRPs(vrpsjson)
		asserted := s.slurm.AssertVRPs()
		log.Infof("Slurm filtering: %v kept, %v removed, %v asserted", len(kept), len(removed), len(asserted))
		vrpsjson = append(kept, asserted...)
	}

	vrps, count, countv4, countv6 := processData(vrpsjson)
	if err != nil {
		return err
	}

	log.Infof("New update (%v uniques, %v total prefixes). %v bytes. Updating sha256 hash %x -> %x",
		len(vrps), count, len(s.lastconverted), s.lasthash, hsum)
	s.lasthash = hsum

	s.server.AddVRPs(vrps)

	serial, _ := s.server.GetCurrentSerial(sessid)
	log.Infof("Updated added, new serial %v", serial)
	if s.sendNotifs {
		log.Debugf("Sending notifications to clients")
		s.server.NotifyClientsLatest()
	}

	s.lockJson.Lock()
	s.exported = prefixfile.VRPList{
		Metadata: prefixfile.MetaData{
			Counts:    len(vrpsjson),
			Buildtime: vrplistjson.Metadata.Buildtime,
		},
		Data: vrpsjson,
	}

	s.lockJson.Unlock()

	if s.metricsEvent != nil {
		var countv4_dup int
		var countv6_dup int
		for _, vrp := range vrps {
			if vrp.Prefix.IP.To4() != nil {
				countv4_dup++
			} else if vrp.Prefix.IP.To16() != nil {
				countv6_dup++
			}
		}
		s.metricsEvent.UpdateMetrics(countv4, countv6, countv4_dup, countv6_dup, s.lastchange, s.lastts, file)
	}
	return nil
}

func (s *state) updateSlurm(file string) error {
	log.Debugf("Refreshing slurm from %v", file)
	data, code, lastrefresh, err := s.fetchConfig.FetchFile(file)
	if err != nil {
		return err
	}
	if lastrefresh {
		LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	buf := bytes.NewBuffer(data)

	slurm, err := prefixfile.DecodeJSONSlurm(buf)
	if err != nil {
		return err
	}
	s.slurm = slurm
	return nil
}

func (s *state) routineUpdate(file string, interval int, slurmFile string) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs, slurm: %v)", file, interval, slurmFile)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		delay := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-delay.C:
		case <-signals:
			log.Debug("Received HUP signal")
		}
		delay.Stop()
		if slurmFile != "" {
			err := s.updateSlurm(slurmFile)
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
		err := s.updateFile(file)
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
	}
}

func (s *state) exporter(wr http.ResponseWriter, r *http.Request) {
	s.lockJson.RLock()
	toExport := s.exported
	s.lockJson.RUnlock()
	enc := json.NewEncoder(wr)
	enc.Encode(toExport)
}

type state struct {
	lastdata      []byte
	lastconverted []byte
	lasthash      []byte
	lastchange    time.Time
	lastts        time.Time
	sendNotifs    bool
	useSerial     int

	fetchConfig *utils.FetchConfig

	server *rtr.Server

	metricsEvent *metricsEvent

	exported prefixfile.VRPList
	lockJson *sync.RWMutex

	slurm *prefixfile.SlurmConfig

	checktime bool
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

func (m *metricsEvent) UpdateMetrics(numIPv4 int, numIPv6 int, numIPv4filtered int, numIPv6filtered int, changed time.Time, refreshed time.Time, file string) {
	NumberOfVRPs.WithLabelValues("ipv4", "filtered", file).Set(float64(numIPv4filtered))
	NumberOfVRPs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(numIPv4))
	NumberOfVRPs.WithLabelValues("ipv6", "filtered", file).Set(float64(numIPv6filtered))
	NumberOfVRPs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(numIPv6))
	LastChange.WithLabelValues(file).Set(float64(changed.UnixNano() / 1e9))
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
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
		SessId:          *SessionID,
		KeepDifference:  3,
		Log:             log.StandardLogger(),
		LogVerbose:      *LogVerbose,

		RefreshInterval: uint32(*RefreshRTR),
		RetryInterval:   uint32(*RetryRTR),
		ExpireInterval:  uint32(*ExpireRTR),
	}

	var me *metricsEvent
	var enableHTTP bool
	if *MetricsAddr != "" {
		initMetrics()
		me = &metricsEvent{}
		enableHTTP = true
	}

	server := rtr.NewServer(sc, me, deh)
	deh.SetVRPManager(server)

	s := state{
		server:       server,
		metricsEvent: me,
		sendNotifs:   *SendNotifs,
		checktime:    *TimeCheck,
		lockJson:     &sync.RWMutex{},

		fetchConfig: utils.NewFetchConfig(),
	}
	s.fetchConfig.UserAgent = *UserAgent
	s.fetchConfig.Mime = *Mime
	s.fetchConfig.EnableEtags = *Etag
	s.fetchConfig.EnableLastModified = *LastModified

	if enableHTTP {
		if *ExportPath != "" {
			http.HandleFunc(*ExportPath, s.exporter)
		}
		go metricHTTP()
	}

	if *Bind == "" && *BindTLS == "" && *BindSSH == "" {
		log.Fatalf("Specify at least a bind address")
	}

	err := s.updateFile(*CacheBin)
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

	slurmFile := *Slurm
	if slurmFile != "" {
		err := s.updateSlurm(slurmFile)
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

	if *Bind != "" {
		go func() {
			sessid, _ := server.GetSessionId(nil)
			log.Infof("StayRTR Server started (sessionID:%d, refresh:%d, retry:%d, expire:%d)", sessid, sc.RefreshInterval, sc.RetryInterval, sc.ExpireInterval)
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
		sshkey, err := ioutil.ReadFile(*SSHKey)
		if err != nil {
			log.Fatal(err)
		}
		private, err := ssh.ParsePrivateKey(sshkey)
		if err != nil {
			log.Fatal("Failed to parse private key: ", err)
		}

		sshConfig := ssh.ServerConfig{}

		log.Infof("Enabling ssh with the following authentications: password=%v, key=%v", *SSHAuthEnablePassword, *SSHAuthEnableKey)
		if *SSHAuthEnablePassword {
			password := *SSHAuthPassword
			if password == "" {
				password = os.Getenv(ENV_SSH_PASSWORD)
			}
			sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				log.Infof("Connected (ssh-password): %v/%v", conn.User(), conn.RemoteAddr())
				if conn.User() != *SSHAuthUser || !bytes.Equal(password, []byte(*SSHAuthPassword)) {
					log.Warnf("Wrong user or password for %v/%v. Disconnecting.", conn.User(), conn.RemoteAddr())
					return nil, errors.New("Wrong user or password")
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
				sshClientKeysToDecodeBytes, err := ioutil.ReadFile(*SSHAuthKeysList)
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
						if strings.HasPrefix(fmt.Sprintf("%v %v", key.Type(), keyBase64), k) {
							log.Infof("Connected (ssh-key): %v/%v with key %v %v (matched with line %v)",
								conn.User(), conn.RemoteAddr(), key.Type(), keyBase64, i+1)
							noKeys = true
							break
						}
					}
					if !noKeys {
						log.Warnf("No key for %v/%v %v %v. Disconnecting.", conn.User(), conn.RemoteAddr(), key.Type(), keyBase64)
						return nil, errors.New("Key not found")
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

}
