package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/prefixfile"
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
	AppVersion = "RTRdump " + rtr.APP_VERSION

	Connect = flag.String("connect", "127.0.0.1:8282", "Connection address")
	OutFile = flag.String("file", "output.json", "Output file")

	InitSerial = flag.Bool("serial", false, "Send serial query instead of reset")
	Serial     = flag.Int("serial.value", 0, "Serial number")
	Session    = flag.Int("session.id", 0, "Session ID")

	FlagVersion = flag.Int("rtr.version", 2, "What RTR version you want to use, Version 2 is draft-ietf-sidrops-8210bis-23")

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
	Data prefixfile.RPKIList

	InitSerial bool
	Serial     uint32
	SessionID  uint16
}

func (c *Client) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu := pdu.(type) {
	case *rtr.PDUIPv4Prefix:
		rj := prefixfile.VRPJson{
			Prefix: pdu.Prefix.String(),
			ASN:    uint32(pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.ROA = append(c.Data.ROA, rj)
		c.Data.Metadata.Counts++

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}
	case *rtr.PDUIPv6Prefix:
		rj := prefixfile.VRPJson{
			Prefix: pdu.Prefix.String(),
			ASN:    uint32(pdu.ASN),
			Length: pdu.MaxLen,
		}
		c.Data.ROA = append(c.Data.ROA, rj)
		c.Data.Metadata.Counts++

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}
	case *rtr.PDURouterKey:
		skiHex := hex.EncodeToString(pdu.SubjectKeyIdentifier)
		rj := prefixfile.BgpSecKeyJson{
			Asn:    uint32(pdu.ASN),
			Pubkey: pdu.SubjectPublicKeyInfo,
			Ski:    skiHex,
		}
		c.Data.BgpSecKeys = append(c.Data.BgpSecKeys, rj)

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}

	case *rtr.PDUASPA:
		if c.Data.ASPA == nil {
			c.Data.ASPA = make([]prefixfile.VAPJson, 0)
		}
		aj := prefixfile.VAPJson{
			CustomerAsid: pdu.CustomerASNumber,
			Providers:    pdu.ProviderASNumbers,
		}

		c.Data.ASPA = append(c.Data.ASPA, aj)

		if *LogDataPDU {
			log.Debugf("Received: %v", pdu)
		}
	case *rtr.PDUEndOfData:
		c.Data.Metadata.SessionID = int(pdu.SessionId)
		c.Data.Metadata.Serial = int(pdu.SerialNumber)
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
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Printf("%s: illegal positional argument(s) provided (\"%s\") - did you mean to provide a flag?\n", os.Args[0], strings.Join(flag.Args(), " "))
		os.Exit(2)
	}
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	targetVersion := rtr.PROTOCOL_VERSION_0
	if *FlagVersion > 2 {
		log.Fatalf("Invalid RTR Version provided, the highest version this release supports is 2")
	}
	if *FlagVersion == 1 {
		targetVersion = rtr.PROTOCOL_VERSION_1
	} else if *FlagVersion == 2 {
		targetVersion = rtr.PROTOCOL_VERSION_2
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	cc := rtr.ClientConfiguration{
		ProtocolVersion: uint8(targetVersion),
		Log:             log.StandardLogger(),
	}

	client := &Client{
		Data: prefixfile.RPKIList{
			Metadata: prefixfile.MetaData{},
			ROA:     make([]prefixfile.VRPJson, 0),
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
					return fmt.Errorf("server key hash %v is different than expected key hash SHA256:%v", serverKeyHash, *SSHServerKey)
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
		if errors.Is(err, io.EOF) && targetVersion == rtr.PROTOCOL_VERSION_2 {
			log.Warnf("EOF From remote side, This might be due to version 2 being requested, try using -rtr.version 1")
		}
		log.Fatal(err)
	}

	var f io.Writer
	if *OutFile != "" {
		ff, err := os.Create(*OutFile)
		if err != nil {
			log.Fatal(err)
		}
		defer ff.Close()
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
