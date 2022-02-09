package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/bgp/stayrtr/cache"
	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/metrics"
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

	MetricsAddr = flag.String("metrics.addr", ":9847", "Metrics address")
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

func main() {
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
		SessId:          *SessionID,
		KeepDifference:  3,
		Log:             log.StandardLogger(),
		LogVerbose:      *LogVerbose,

		RefreshInterval: uint32(*RefreshRTR),
		RetryInterval:   uint32(*RetryRTR),
		ExpireInterval:  uint32(*ExpireRTR),
	}

	var me *metrics.MetricsEvent
	var enableHTTP bool
	if *MetricsAddr != "" {
		//initMetrics()
		me = &metrics.MetricsEvent{}
		enableHTTP = true
	}

	server := rtr.NewServer(sc, me, deh)
	deh.SetVRPManager(server)

	s := cache.NewVRPCache(server, *TimeCheck, *SendNotifs)
	s.FetchConfig.UserAgent = *UserAgent
	s.FetchConfig.Mime = *Mime
	s.FetchConfig.EnableEtags = *Etag
	s.FetchConfig.EnableLastModified = *LastModified

	if enableHTTP {
		if *ExportPath != "" {
			http.HandleFunc(*ExportPath, s.Exporter)
		}
		go metrics.MetricHTTP(*MetricsPath, *MetricsAddr)
	}

	if *Bind == "" && *BindTLS == "" && *BindSSH == "" {
		log.Fatalf("Specify at least a bind address")
	}

	_, err := s.UpdateFile(*CacheBin)
	if err != nil {
		switch err.(type) {
		case cache.HttpNotModified:
			log.Info(err)
		case cache.IdenticalFile:
			log.Info(err)
		case cache.IdenticalEtag:
			log.Info(err)
		default:
			log.Errorf("Error updating: %v", err)
		}
	}

	slurmFile := *Slurm
	if slurmFile != "" {
		_, err := s.UpdateSlurm(slurmFile)
		if err != nil {
			switch err.(type) {
			case cache.HttpNotModified:
				log.Info(err)
			case cache.IdenticalEtag:
				log.Info(err)
			default:
				log.Errorf("Slurm: %v", err)
			}
		}
		if !*SlurmRefresh {
			slurmFile = ""
		}
	}

	// Initial calculation of state (after fetching cache + slurm)
	err = s.UpdateFromNewState()
	if err != nil {
		log.Warnf("Error setting up intial state: %s", err)
	}

	if *Bind != "" {
		go func() {
			sessid := server.GetSessionId()
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
		sshkey, err := os.ReadFile(*SSHKey)
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
			sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, suppliedPassword []byte) (*ssh.Permissions, error) {
				log.Infof("Connected (ssh-password): %v/%v", conn.User(), conn.RemoteAddr())
				if conn.User() != *SSHAuthUser || !bytes.Equal(suppliedPassword, []byte(password)) {
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

	s.RoutineUpdate(*CacheBin, *RefreshInterval, slurmFile)

	return nil
}
