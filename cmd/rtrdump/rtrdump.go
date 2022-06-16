package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/bgp/stayrtr/cache"
	rtr "github.com/bgp/stayrtr/lib"
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

var (
	version    = ""
	buildinfos = ""
	AppVersion = "RTRdump " + version + " " + buildinfos

	Connect = flag.String("connect", "127.0.0.1:8282", "Connection address")
	OutFile = flag.String("file", "output.json", "Output file")

	InitSerial = flag.Bool("serial", false, "Send serial query instead of reset")
	Serial     = flag.Int("serial.value", 0, "Serial number")
	Session    = flag.Int("session.id", 0, "Session ID")

	ConnType     = flag.String("type", "plain", "Type of connection: plain, tls or ssh")
	ValidateCert = flag.Bool("tls.validate", true, "Validate TLS")

	ValidateSSH     = flag.Bool("ssh.validate", false, "Validate SSH key")
	SSHServerKey    = flag.String("ssh.validate.key", "", "SSH server key SHA256 to validate")
	SSHAuth         = flag.String("ssh.method", "none", "Select SSH method (none, password or key)")
	SSHAuthUser     = flag.String("ssh.auth.user", "rpki", "SSH user")
	SSHAuthPassword = flag.String("ssh.auth.password", "", fmt.Sprintf("SSH password (if blank, will use envvar %v)", ENV_SSH_PASSWORD))
	SSHAuthKey      = flag.String("ssh.auth.key", "id_rsa", fmt.Sprintf("SSH key file (if blank, will use envvar %v)", ENV_SSH_KEY))

	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")

	LogLevel   = flag.String("loglevel", "info", "Log level")
	LogDataPDU = flag.Bool("datapdu", false, "Log data PDU")
	Version    = flag.Bool("version", false, "Print version")

	typeToId = map[string]int{
		"plain": rtr.TYPE_PLAIN,
		"tls":   rtr.TYPE_TLS,
		"ssh":   rtr.TYPE_SSH,
	}
	authToId = map[string]int{
		"none":     METHOD_NONE,
		"password": METHOD_PASSWORD,
		"key":      METHOD_KEY,
	}
)

type Client struct {
	Data cache.VRPList

	InitSerial bool
	Serial     uint32
	SessionID  uint16
}

func (c *Client) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu := pdu.(type) {
	case *rtr.PDUIPv4Prefix:
		rj := cache.VRPJson{
			Prefix: pdu.Prefix.String(),
			ASN:    uint32(pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.Data = append(c.Data.Data, rj)
		c.Data.Metadata.Counts++

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}
	case *rtr.PDUIPv6Prefix:
		rj := cache.VRPJson{
			Prefix: pdu.Prefix.String(),
			ASN:    uint32(pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.Data = append(c.Data.Data, rj)
		c.Data.Metadata.Counts++

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}
	case *rtr.PDUEndOfData:
		cs.Disconnect()
		log.Debugf("Received: %v", pdu)
	case *rtr.PDUCacheResponse:
		log.Debugf("Received: %v", pdu)
	default:
		log.Debugf("Received: %v", pdu)
		cs.Disconnect()
	}
}

func (c *Client) ClientConnected(cs *rtr.ClientSession) {
	if c.InitSerial {
		cs.SendSerialQuery(c.SessionID, c.Serial)
	} else {
		cs.SendResetQuery()
	}
}

func (c *Client) ClientDisconnected(cs *rtr.ClientSession) {

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

	cc := rtr.ClientConfiguration{
		ProtocolVersion: rtr.PROTOCOL_VERSION_1,
		Log:             log.StandardLogger(),
	}

	client := &Client{
		Data: cache.VRPList{
			Metadata: cache.MetaData{},
			Data:     make([]cache.VRPJson, 0),
		},
		InitSerial: *InitSerial,
		Serial:     uint32(*Serial),
		SessionID:  uint16(*Session),
	}

	clientSession := rtr.NewClientSession(cc, client)

	configTLS := &tls.Config{
		InsecureSkipVerify: !*ValidateCert,
	}
	configSSH := &ssh.ClientConfig{
		Auth: make([]ssh.AuthMethod, 0),
		User: *SSHAuthUser,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			serverKeyHash := ssh.FingerprintSHA256(key)
			if *ValidateSSH {
				if serverKeyHash != fmt.Sprintf("SHA256:%v", *SSHServerKey) {
					return errors.New(fmt.Sprintf("Server key hash %v is different than expected key hash SHA256:%v", serverKeyHash, *SSHServerKey))
				}
			}
			log.Infof("Connected to server %v via ssh. Fingerprint: %v", remote.String(), serverKeyHash)
			return nil
		},
	}
	if authType, ok := authToId[*SSHAuth]; ok {
		if authType == METHOD_PASSWORD {
			password := *SSHAuthPassword
			if password == "" {
				password = os.Getenv(ENV_SSH_PASSWORD)
			}
			configSSH.Auth = append(configSSH.Auth, ssh.Password(password))
		} else if authType == METHOD_KEY {
			var keyBytes []byte
			var err error
			if *SSHAuthKey == "" {
				keyBytesStr := os.Getenv(ENV_SSH_KEY)
				keyBytes = []byte(keyBytesStr)
			} else {
				keyBytes, err = os.ReadFile(*SSHAuthKey)
				if err != nil {
					log.Fatal(err)
				}
			}
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil {
				log.Fatal(err)
			}
			configSSH.Auth = append(configSSH.Auth, ssh.PublicKeys(signer))
		}
	} else {
		log.Fatalf("Auth type %v unknown", *SSHAuth)
	}

	log.Infof("Connecting with %v to %v", *ConnType, *Connect)
	err := clientSession.Start(*Connect, typeToId[*ConnType], configTLS, configSSH)
	if err != nil {
		log.Fatal(err)
	}

	var f io.Writer
	if *OutFile != "" {
		ff, err := os.Create(*OutFile)
		defer ff.Close()
		if err != nil {
			log.Fatal(err)
		}
		f = ff
	} else {
		f = os.Stdout
	}

	enc := json.NewEncoder(f)
	err = enc.Encode(client.Data)
	if err != nil {
		log.Fatal(err)
	}
}
