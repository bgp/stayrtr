package rtrlib

import (
	"bytes"
	"context"
	"crypto/tls"
        "encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
        "net/http"
	"net/netip"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func GenerateSessionId() uint16 {
	return uint16(rand.Intn(math.MaxUint16 + 1))
}

type RTRServerEventHandler interface {
	ClientConnected(*Client)
	ClientDisconnected(*Client)
	HandlePDU(*Client, PDU)
}

type RTREventHandler interface {
	RequestCache(*Client)
	RequestNewVersion(*Client, uint16, uint32)
}

// This is a general interface for things like a VRP, BGPsec Router key or ASPA object
// Be sure to have all of these as pointers, or SetFlag() cannot work!
type SendableData interface {
	Copy() SendableData
	Equals(SendableData) bool
	HashKey() string
	String() string
	Type() string
	SetFlag(uint8)
	GetFlag() uint8
}

// This handles things like ROAs, BGPsec Router keys, ASPA info etc
type SendableDataManager interface {
	GetCurrentSerial() (uint32, bool)
	GetSessionId(uint8) uint16
	GetCurrentSDs() ([]SendableData, bool)
	GetSDsSerialDiff(uint32) ([]SendableData, bool)
}

type DefaultRTREventHandler struct {
	sdManager SendableDataManager
	Log       Logger
}

func (e *DefaultRTREventHandler) SetSDManager(m SendableDataManager) {
	e.sdManager = m
}

func (e *DefaultRTREventHandler) RequestCache(c *Client) {
	if e.Log != nil {
		e.Log.Debugf("%v > Request Cache", c)
	}
	sessionId := e.sdManager.GetSessionId(c.GetVersion())
	serial, valid := e.sdManager.GetCurrentSerial()
	if !valid {
		c.SendNoDataError()
		if e.Log != nil {
			e.Log.Debugf("%v < No data", c)
		}
	} else {
		data, exists := e.sdManager.GetCurrentSDs()
		if !exists {
			c.SendInternalError()
			if e.Log != nil {
				e.Log.Debugf("%v < Internal error requesting cache (does not exists)", c)
			}
		} else {
			c.SendSDs(sessionId, serial, data)
			if e.Log != nil {
				e.Log.Debugf("%v < Sent cache (current serial %d, session: %d)", c, serial, sessionId)
			}
		}
	}
}

func (e *DefaultRTREventHandler) RequestNewVersion(c *Client, sessionId uint16, serialNumber uint32) {
	if e.Log != nil {
		e.Log.Debugf("%v > Request New Version", c)
	}
	serverSessionId := e.sdManager.GetSessionId(c.GetVersion())
	if sessionId != serverSessionId {
		c.SendCorruptData()
		if e.Log != nil {
			e.Log.Debugf("%v < Invalid request (client asked for session %d but server is at %d)", c, sessionId, serverSessionId)
		}
		c.Disconnect()
		return
	}
	serial, valid := e.sdManager.GetCurrentSerial()
	if !valid {
		c.SendNoDataError()
		if e.Log != nil {
			e.Log.Debugf("%v < No data", c)
		}
	} else {
		data, exists := e.sdManager.GetSDsSerialDiff(serialNumber)
		if !exists {
			c.SendCacheReset()
			if e.Log != nil {
				e.Log.Debugf("%v < Sent cache reset", c)
			}
		} else {
			c.SendSDs(sessionId, serial, data)
			if e.Log != nil {
				e.Log.Debugf("%v < Sent cache (current serial %d, session from client: %d)", c, serial, sessionId)
			}
		}
	}
}

type Server struct {
	baseVersion uint8
	clientlock  *sync.RWMutex
	clients     []*Client
	sessId      []uint16
	connected   int
	maxconn     int

	sshconfig *ssh.ServerConfig

	handler        RTRServerEventHandler
	simpleHandler  RTREventHandler
	enforceVersion bool
	disableBGPSec  bool
	disableASPA    bool
	enableNODELAY  bool

	sdlock          *sync.RWMutex
	sdListDiff      [][]SendableData
	sdCurrent       []SendableData
	sdCurrentSerial uint32
	keepDiff        int

	pduRefreshInterval uint32
	pduRetryInterval   uint32
	pduExpireInterval  uint32

	log        Logger
	logverbose bool
}

type ServerConfiguration struct {
	MaxConn         int
	ProtocolVersion uint8
	EnforceVersion  bool
	KeepDifference  int

	SessId int

	DisableBGPSec	bool
	DisableASPA	bool
	EnableNODELAY	bool

	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32

	Log        Logger
	LogVerbose bool
}

func NewServer(configuration ServerConfiguration, handler RTRServerEventHandler, simpleHandler RTREventHandler) *Server {
	sessids := make([]uint16, 0, int(configuration.ProtocolVersion) + 1)
	s := GenerateSessionId()
	for i := 0; i <= int(configuration.ProtocolVersion); i++ {
		sessids = append(sessids, s + uint16(100 * i))
	}

	refreshInterval := uint32(3600)
	if configuration.RefreshInterval != 0 {
		refreshInterval = configuration.RefreshInterval
	}
	retryInterval := uint32(600)
	if configuration.RetryInterval != 0 {
		retryInterval = configuration.RetryInterval
	}
	expireInterval := uint32(7200)
	if configuration.ExpireInterval != 0 {
		expireInterval = configuration.ExpireInterval
	}

	return &Server{
		sdlock:       &sync.RWMutex{},
		sdListDiff:   make([][]SendableData, 0),
		sdCurrent:    make([]SendableData, 0),
		keepDiff:     configuration.KeepDifference,

		clientlock:     &sync.RWMutex{},
		clients:        make([]*Client, 0),
		sessId:         sessids,
		maxconn:        configuration.MaxConn,
		baseVersion:    configuration.ProtocolVersion,

		enforceVersion: configuration.EnforceVersion,
		disableBGPSec:	configuration.DisableBGPSec,
		disableASPA:	configuration.DisableASPA,

		pduRefreshInterval: refreshInterval,
		pduRetryInterval:   retryInterval,
		pduExpireInterval:  expireInterval,

		handler:        handler,
		simpleHandler:  simpleHandler,

		log:        configuration.Log,
		logverbose: configuration.LogVerbose,
	}
}

func ConvertSDListToMap(SDs []SendableData) map[string]uint8 {
	sdMap := make(map[string]uint8, len(SDs))
	for _, v := range SDs {
		sdMap[v.HashKey()] = v.GetFlag()
	}
	return sdMap
}

func ComputeDiff(newSDs, prevSDs []SendableData, populateUnchanged bool) (added, removed, unchanged []SendableData) {
	added = make([]SendableData, 0)
	removed = make([]SendableData, 0)
	unchanged = make([]SendableData, 0)

	newSDsMap := ConvertSDListToMap(newSDs)
	prevSDsMap := ConvertSDListToMap(prevSDs)

	for _, item := range newSDs {
		_, exists := prevSDsMap[item.HashKey()]
		if !exists {
			rcopy := item.Copy()
			rcopy.SetFlag(FLAG_ADDED)
			added = append(added, rcopy)
		}
	}
	for _, item := range prevSDs {
		_, exists := newSDsMap[item.HashKey()]
		if !exists {
			rcopy := item.Copy()
			rcopy.SetFlag(FLAG_REMOVED)
			removed = append(removed, rcopy)
		} else if populateUnchanged {
			rcopy := item.Copy()
			unchanged = append(unchanged, rcopy)
		}
	}

	return added, removed, unchanged
}

func ApplyDiff(diff, prevSDs []SendableData) []SendableData {
	newSDs := make([]SendableData, 0)
	diffMap := ConvertSDListToMap(diff)
	prevSDsMap := ConvertSDListToMap(prevSDs)

	for _, item := range prevSDs {
		_, exists := diffMap[item.HashKey()]
		if !exists {
			rcopy := item.Copy()
			newSDs = append(newSDs, rcopy)
		}
	}
	for _, item := range diff {
		if item.GetFlag() == FLAG_ADDED {
			rcopy := item.Copy()
			newSDs = append(newSDs, rcopy)
		} else if item.GetFlag() == FLAG_REMOVED {
			citem, exists := prevSDsMap[item.HashKey()]
			if !exists {
				rcopy := item.Copy()
				newSDs = append(newSDs, rcopy)
			} else {
				if citem == FLAG_REMOVED {
					rcopy := item.Copy()
					newSDs = append(newSDs, rcopy)
				}
			}
		}

	}
	return newSDs
}

func (s *Server) GetSessionId(version uint8) uint16 {
	return s.sessId[version]
}

func (s *Server) GetCurrentSDs() ([]SendableData, bool) {
	s.sdlock.RLock()
	sd := s.sdCurrent
	s.sdlock.RUnlock()
	return sd, true
}

func (s *Server) GetSDsSerialDiff(serial uint32) ([]SendableData, bool) {
	s.sdlock.RLock()
	sd, ok := s.getSDsSerialDiff(serial)
	s.sdlock.RUnlock()
	return sd, ok
}

func (s *Server) getSDsSerialDiff(serial uint32) ([]SendableData, bool) {
	if serial == s.sdCurrentSerial {
		return []SendableData{}, true
	}
	if serial > s.sdCurrentSerial {
		return nil, false
	}
	diff := int(s.sdCurrentSerial - serial)
	if diff > len(s.sdListDiff) {
		return nil, false
	}

	sd := s.sdListDiff[len(s.sdListDiff) - diff]
	return sd, true
}

func (s *Server) GetCurrentSerial() (uint32, bool) {
	s.sdlock.RLock()
	serial, valid := s.getCurrentSerial()
	s.sdlock.RUnlock()
	return serial, valid
}

func (s *Server) getCurrentSerial() (uint32, bool) {
	return s.sdCurrentSerial, len(s.sdCurrent) > 0
}

func (s *Server) generateSerial() uint32 {
	newserial := s.sdCurrentSerial
	if len(s.sdCurrent) > 0 {
		newserial++
	}
	return newserial
}

func (s *Server) CountSDs() int {
	s.sdlock.RLock()
	defer s.sdlock.RUnlock()

	return len(s.sdCurrent)
}

func (s *Server) AddData(new []SendableData) bool {
	s.sdlock.RLock()

	added, removed, _ := ComputeDiff(new, s.sdCurrent, false)
	if s.log != nil && s.logverbose {
		s.log.Debugf("Computed diff: added (%v), removed (%v)", added, removed)
	} else if s.log != nil {
		s.log.Debugf("Computed diff: added (%d), removed (%d)", len(added), len(removed))
	}
	curDiff := append(added, removed...)
	s.sdlock.RUnlock()

	if len(curDiff) == 0 {
		return false
	} else {
		s.AddSDsDiff(curDiff)
		return true
	}
}

func (s *Server) AddSDsDiff(diff []SendableData) {
	s.sdlock.RLock()
	nextDiff := make([][]SendableData, len(s.sdListDiff) + 1)
	for i, prevSDs := range s.sdListDiff {
		nextDiff[i] = ApplyDiff(diff, prevSDs)
	}
	newSDCurrent := ApplyDiff(diff, s.sdCurrent)
	s.sdlock.RUnlock()

	s.sdlock.Lock()
	defer s.sdlock.Unlock()
	newserial := s.generateSerial()

	nextDiff = append(nextDiff, diff)
	if s.keepDiff > 0 && len(nextDiff) > s.keepDiff {
		nextDiff = nextDiff[len(nextDiff) - s.keepDiff:]
	}

	s.sdListDiff = nextDiff
	s.sdCurrent = newSDCurrent
	s.sdCurrentSerial = newserial
}

func (s *Server) SetBaseVersion(version uint8) {
	s.baseVersion = version
}

func (s *Server) SetVersionEnforced(adapt bool) {
	s.enforceVersion = adapt
}

func (s *Server) SetMaxConnections(maxconn int) {
	if s.connected > maxconn {
		todisconnect := s.connected - maxconn
		clients := s.GetClientList()
		if s.log != nil {
			s.log.Debugf("Too many clients connected, disconnecting first %v", todisconnect)
		}
		for i := 0; i < todisconnect; i++ {
			if len(clients) > i {
				clients[i].Disconnect()
			}
		}
	}
	s.maxconn = maxconn
}

func (s *Server) GetMaxConnections() int {
	return s.maxconn
}

func (s *Server) GetClientRemoteAddrs(w http.ResponseWriter, r *http.Request) {
	clients := s.GetClientList()
	out := make([]string, len(clients))
	for i, c := range clients {
		out[i] = c.GetRemoteAddress().String()
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) ClientConnected(c *Client) {
	s.clientlock.Lock()
	s.clients = append(s.clients, c)
	s.connected++
	s.clientlock.Unlock()

	if s.handler != nil {
		s.handler.ClientConnected(c)
	}
}

func (s *Server) ClientDisconnected(c *Client) {
	s.clientlock.Lock()
	tmpclients := make([]*Client, 0)
	for _, cc := range s.clients {
		if cc != c {
			tmpclients = append(tmpclients, cc)
		}
	}
	s.clients = tmpclients
	s.connected--
	s.clientlock.Unlock()

	if s.handler != nil {
		s.handler.ClientDisconnected(c)
	}
}

func (s *Server) HandlePDU(c *Client, pdu PDU) {
	if s.enforceVersion && c.GetVersion() != s.baseVersion {
		// Enforce a single version
		if s.log != nil {
			s.log.Debugf("Client %v uses version %v and server is using %v", c.String(), c.GetVersion(), s.baseVersion)
		}
		c.SendWrongVersionError()
		c.Disconnect()
	}
	if c.GetVersion() > s.baseVersion {
		// Downgrade
		c.SetVersion(s.baseVersion)
	}

	if s.handler != nil {
		s.handler.HandlePDU(c, pdu)
	}
}

func (s *Server) RequestCache(c *Client) {
	if s.simpleHandler != nil {
		s.simpleHandler.RequestCache(c)
	}
}

func (s *Server) RequestNewVersion(c *Client, sessionId uint16, serial uint32) {
	if s.simpleHandler != nil {
		s.simpleHandler.RequestNewVersion(c, sessionId, serial)
	}
}

func (s *Server) Start(bind string) error {
	tcplist, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	return s.loopTCP(tcplist, "tcp", s.acceptClientTCP)
}

func (s *Server) acceptClientTCP(tcpconn net.Conn) error {
	if !s.enableNODELAY {
		tc, ok := tcpconn.(*net.TCPConn)
		if ok {
			tc.SetNoDelay(false)
		}
	}

	client := ClientFromConn(tcpconn, s, s)
	client.log = s.log
	if s.enforceVersion {
		client.SetVersion(s.baseVersion)
	}
	client.SetIntervals(s.pduRefreshInterval, s.pduRetryInterval, s.pduExpireInterval)
	if s.disableBGPSec {
		client.DisableBGPsec()
	}
	if s.disableASPA {
		client.DisableASPA()
	}
	go client.Start()
	return nil
}

func (s *Server) acceptClientSSH(tcpconn net.Conn) error {
	_, chans, reqs, err := ssh.NewServerConn(tcpconn, s.sshconfig)
	if err != nil {
		return err
	}

	go func() {
		s.connected++
		cont := true
		for cont {
			select {
			case req := <-reqs:
				if req != nil && req.WantReply {
					req.Reply(false, nil)
				} else if req == nil {
					cont = false
					break
				}
			case newChannel := <-chans:
				if newChannel != nil && newChannel.ChannelType() != "session" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				} else if newChannel == nil {
					cont = false
					break
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					if s.log != nil {
						s.log.Errorf("Could not accept channel: %v", err)
					}
					cont = false
					break
				}
				for req := range requests {
					if req != nil && req.Type == "subsystem" && bytes.Equal(req.Payload, []byte{0, 0, 0, 8, 114, 112, 107, 105, 45, 114, 116, 114}) {
						err := req.Reply(true, nil)
						if err != nil {
							if s.log != nil {
								s.log.Errorf("Could not accept channel: %v", err)
							}
							cont = false
							break
						}
						client := ClientFromConnSSH(tcpconn, channel, s, s)
						client.log = s.log
						if s.enforceVersion {
							client.SetVersion(s.baseVersion)
						}
						client.SetIntervals(s.pduRefreshInterval, s.pduRetryInterval, s.pduExpireInterval)
						client.Start()
					} else {
						cont = false
						break
					}

				}
			}
		}
		s.connected--
		tcpconn.Close()
	}()
	return nil
}

type ClientCallback func(net.Conn) error

func (s *Server) loopTCP(tcplist net.Listener, logEnv string, clientCallback ClientCallback) error {
	for {
		tcpconn, err := tcplist.Accept()
		if err != nil {
			if s.log != nil {
				s.log.Errorf("Failed to accept %s connection: %s", logEnv, err)
			}
			continue
		}

		if s.maxconn > 0 && s.connected >= s.maxconn {
			if s.log != nil {
				s.log.Warnf("Could not accept %s connection from %v (not enough slots available: %d)", logEnv, tcpconn.RemoteAddr(), s.maxconn)
			}
			tcpconn.Close()
		} else {
			if s.log != nil {
				s.log.Infof("Accepted %s connection from %v (%d/%d)", logEnv, tcpconn.RemoteAddr(), s.connected+1, s.maxconn)
			}
			if clientCallback != nil {
				err := clientCallback(tcpconn)
				if err != nil && s.log != nil {
					s.log.Errorf("Error with %s client %v: %v", logEnv, tcpconn.RemoteAddr(), err)
				}
			}
		}
	}
}

func (s *Server) StartSSH(bind string, config *ssh.ServerConfig) error {
	tcplist, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	s.sshconfig = config
	return s.loopTCP(tcplist, "ssh", s.acceptClientSSH)
}

func (s *Server) StartTLS(bind string, config *tls.Config) error {
	tcplist, err := tls.Listen("tcp", bind, config)
	if err != nil {
		return err
	}
	return s.loopTCP(tcplist, "tls", s.acceptClientTCP)
}

func (s *Server) GetClientList() []*Client {
	s.clientlock.RLock()
	list := make([]*Client, len(s.clients))
	copy(list, s.clients)
	s.clientlock.RUnlock()
	return list
}

func (s *Server) NotifyClientsLatest() {
	serial, _ := s.GetCurrentSerial()
	clients := s.GetClientList()
	for _, c := range clients {
		c.Notify(s.GetSessionId(c.GetVersion()), serial)
	}
}

func ClientFromConn(tcpconn net.Conn, handler RTRServerEventHandler, simpleHandler RTREventHandler) *Client {
	return &Client{
		tcpconn:       tcpconn,
		rd:            tcpconn,
		wr:            tcpconn,
		handler:       handler,
		simpleHandler: simpleHandler,
		transmits:     make(chan PDU, 256),
	}
}

func ClientFromConnSSH(tcpconn net.Conn, channel ssh.Channel, handler RTRServerEventHandler, simpleHandler RTREventHandler) *Client {
	client := ClientFromConn(tcpconn, handler, simpleHandler)
	client.rd = channel
	client.wr = channel
	return client
}

type Client struct {
	version       uint8
	versionset    bool
	tcpconn       net.Conn
	rd            io.Reader
	wr            io.Writer
	handler       RTRServerEventHandler
	simpleHandler RTREventHandler
	curserial     uint32

	transmits chan PDU
	cancel    context.CancelFunc

	enforceVersion      bool
	disableVersionCheck bool

	refreshInterval uint32
	retryInterval   uint32
	expireInterval  uint32

	dontSendBGPsecKeys bool
	dontSendASPA       bool

	log Logger
}

func (c *Client) String() string {
	return fmt.Sprintf("%v (v%v) / Serial: %v", c.tcpconn.RemoteAddr(), c.version, c.curserial)
}

func (c *Client) GetRemoteAddress() net.Addr {
	return c.tcpconn.RemoteAddr()
}

func (c *Client) GetLocalAddress() net.Addr {
	return c.tcpconn.LocalAddr()
}

func (c *Client) GetVersion() uint8 {
	return c.version
}

func (c *Client) DisableBGPsec() {
	c.dontSendBGPsecKeys = true
}

func (c *Client) DisableASPA() {
	c.dontSendASPA = true
}

func (c *Client) SetIntervals(refreshInterval uint32, retryInterval uint32, expireInterval uint32) {
	c.refreshInterval = refreshInterval
	c.retryInterval = retryInterval
	c.expireInterval = expireInterval
}

func (c *Client) SetVersion(newversion uint8) {
	c.versionset = true
	c.version = newversion
}

func (c *Client) SetDisableVersionCheck(disableCheck bool) {
	c.disableVersionCheck = disableCheck
}

func (c *Client) checkVersion(newversion uint8) error {
	if (!c.versionset || newversion == c.version) && (newversion == PROTOCOL_VERSION_2 || newversion == PROTOCOL_VERSION_1 || newversion == PROTOCOL_VERSION_0) {
		c.SetVersion(newversion)
	} else {
		if c.log != nil {
			c.log.Debugf("%v: has bad version (received: v%v, current: v%v) error", c.String(), newversion, c.version)
		}
		c.SendWrongVersionError()
		c.Disconnect()
		return fmt.Errorf("%v: has bad version (received: v%v, current: v%v)", c.String(), newversion, c.version)
	}
	return nil
}

func (c *Client) passSimpleHandler(pdu PDU) {
	if c.simpleHandler != nil {
		switch pduConv := pdu.(type) {
		case *PDUSerialQuery:
			c.simpleHandler.RequestNewVersion(c, pduConv.SessionId, pduConv.SerialNumber)
		case *PDUResetQuery:
			c.simpleHandler.RequestCache(c)
		default:
			// not a proper client packet
		}
	}
}

func (c *Client) sendLoop(ctx context.Context) error {
	for {
		select {
		case pdu := <-c.transmits:
			c.wr.Write(pdu.Bytes())
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Client) readLoop(ctx context.Context) error {
	buf := make([]byte, 8000)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			length, err := c.rd.Read(buf)
			if err != nil || length == 0 {
				if c.log != nil {
					c.log.Debugf("Error %v", err)
				}
				c.Disconnect()
				return err
			}

			pkt := buf[0:length]
			dec, err := DecodeBytes(pkt)
			if err != nil || dec == nil {
				if c.log != nil {
					c.log.Errorf("Error %v", err)
				}
				c.Disconnect()
				return err
			}
			if !c.disableVersionCheck {
				if err := c.checkVersion(dec.GetVersion()); err != nil {
					// checkVersion returns an error if it issued a disconnect
					return err
				}
			}
			if c.log != nil {
				c.log.Debugf("%v: Received %v", c.String(), dec)
			}

			if c.enforceVersion {
				if !IsCorrectPDUVersion(dec, c.version) {
					if c.log != nil {
						c.log.Debugf("Bad version error")
					}
					c.SendWrongVersionError()
					c.Disconnect()
					return fmt.Errorf("%s: bad version error", c.String())
				}
			}

			switch pduconv := dec.(type) {
			case *PDUSerialQuery:
				c.curserial = pduconv.SerialNumber
			}

			if c.handler != nil {
				c.handler.HandlePDU(c, dec)
			}

			c.passSimpleHandler(dec)
		}
	}
}


func (c *Client) Start() {
	defer c.tcpconn.Close()

	if c.handler != nil {
		c.handler.ClientConnected(c)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	c.cancel = cancel
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return c.sendLoop(ctx)
	})

	eg.Go(func() error {
		return c.readLoop(ctx)
	})

	eg.Wait()
}

func (c *Client) Notify(sessionId uint16, serialNumber uint32) {
	pdu := &PDUSerialNotify{
		SessionId:    sessionId,
		SerialNumber: serialNumber,
	}
	c.SendPDU(pdu)
}

type VRP struct {
	Prefix netip.Prefix
	ASN    uint32
	MaxLen uint8
	Flags  uint8
}

func (r *VRP) Type() string {
	return "VRP"
}

func (r *VRP) String() string {
	return fmt.Sprintf("VRP %v -> /%v, AS%v, Flags: %v", r.Prefix.String(), r.MaxLen, r.ASN, r.Flags)
}

func (vrp *VRP) HashKey() string {
	return fmt.Sprintf("%v-%v-%v", vrp.Prefix.String(), vrp.MaxLen, vrp.ASN)
}

func (r1 *VRP) Equals(r2 SendableData) bool {
	if r1.Type() != r2.Type() {
		return false
	}

	r2True := r2.(*VRP)

	return r1.MaxLen == r2True.MaxLen && r1.ASN == r2True.ASN && r1.Prefix == r2True.Prefix
}

func (r1 *VRP) Copy() SendableData {
	return &VRP{
		Prefix: r1.Prefix,
		ASN:    r1.ASN,
		MaxLen: r1.MaxLen,
		Flags:  r1.Flags}
}

func (r1 *VRP) SetFlag(f uint8) {
	r1.Flags = f
}

func (r1 *VRP) GetFlag() uint8 {
	return r1.Flags
}

type BgpsecKey struct {
	ASN    uint32
	Pubkey []byte
	Ski    []byte
	Flags  uint8
}

func (brk *BgpsecKey) Type() string {
	return "BGPsecKey"
}

func (brk *BgpsecKey) String() string {
	return fmt.Sprintf("BGPsec AS%v -> %x, Flags: %v", brk.ASN, brk.Ski, brk.Flags)
}

func (brk *BgpsecKey) HashKey() string {
	return fmt.Sprintf("%v-%x-%x", brk.ASN, brk.Ski, brk.Pubkey)
}

func (r1 *BgpsecKey) Equals(r2 SendableData) bool {
	if r1.Type() != r2.Type() {
		return false
	}

	r2True := r2.(*BgpsecKey)
	return r1.ASN == r2True.ASN && bytes.Equal(r1.Pubkey, r2True.Pubkey) && bytes.Equal(r1.Ski, r2True.Ski)
}

func (brk *BgpsecKey) Copy() SendableData {
	cop := BgpsecKey{
		ASN:    brk.ASN,
		Pubkey: make([]byte, len(brk.Pubkey)),
		Ski:    make([]byte, len(brk.Ski)),
		Flags:  brk.Flags,
	}
	copy(cop.Pubkey, brk.Pubkey)
	copy(cop.Ski, brk.Ski)
	return &cop
}

func (brk *BgpsecKey) SetFlag(f uint8) {
	brk.Flags = f
}

func (brk *BgpsecKey) GetFlag() uint8 {
	return brk.Flags
}

type VAP struct {
	Flags       uint8
	CustomerASN uint32
	Providers   []uint32
}

func (vap *VAP) Type() string {
	return "ASPA"
}

func (vap *VAP) String() string {
	return fmt.Sprintf("ASPA AS%v -> Providers: %v", vap.CustomerASN, vap.Providers)
}

func (vap *VAP) HashKey() string {
	return fmt.Sprintf("%v-%v", vap.CustomerASN, vap.Providers)
}

func (r1 *VAP) Equals(r2 SendableData) bool {
	if r1.Type() != r2.Type() {
		return false
	}

	r2True := r2.(*VAP)
	return r1.CustomerASN == r2True.CustomerASN && fmt.Sprint(r1.Providers) == fmt.Sprint(r2True.Providers) /*This could be made faster*/
}

func (vap *VAP) Copy() SendableData {
	cop := VAP{
		CustomerASN: vap.CustomerASN,
		Flags:       vap.Flags,
		Providers:   make([]uint32, 0),
	}
	cop.Providers = append(cop.Providers, vap.Providers...)
	return &cop
}

func (vap *VAP) SetFlag(f uint8) {
	vap.Flags = f
}

func (vap *VAP) GetFlag() uint8 {
	return vap.Flags
}

func (c *Client) SendSDs(sessionId uint16, serialNumber uint32, data []SendableData) {
	pduBegin := &PDUCacheResponse{
		SessionId: sessionId,
	}
	c.SendPDU(pduBegin)
	for _, item := range data {
		c.SendData(item.Copy())
	}
	pduEnd := &PDUEndOfData{
		SessionId:    sessionId,
		SerialNumber: serialNumber,

		RefreshInterval: c.refreshInterval,
		RetryInterval:   c.retryInterval,
		ExpireInterval:  c.expireInterval,
	}
	c.SendPDU(pduEnd)
}

func (c *Client) SendCacheReset() {
	pdu := &PDUCacheReset{}
	c.SendPDU(pdu)
}

func (c *Client) SendInternalError() {
	pdu := &PDUErrorReport{
		ErrorCode: PDU_ERROR_INTERNALERR,
		ErrorMsg:  "Unknown internal error",
	}
	c.SendPDU(pdu)
}

func (c *Client) SendNoDataError() {
	pdu := &PDUErrorReport{
		ErrorCode: PDU_ERROR_NODATA,
		ErrorMsg:  "No data available",
	}
	c.SendPDU(pdu)
}

func (c *Client) SendCorruptData() {
	pdu := &PDUErrorReport{
		ErrorCode: PDU_ERROR_CORRUPTDATA,
		ErrorMsg:  "Session ID mismatch: client is desynchronized",
	}
	c.SendPDU(pdu)
}

func (c *Client) SendWrongVersionError() {
	pdu := &PDUErrorReport{
		ErrorCode: PDU_ERROR_BADPROTOVERSION,
		ErrorMsg:  "Bad protocol version",
	}
	c.SendPDU(pdu)
}

// Converts a SendableData to a PDU and sends it to the client
func (c *Client) SendData(sd SendableData) {
	switch t := sd.(type) {
	case *VRP:

		if t.Prefix.Addr().Is6() {
			pdu := &PDUIPv6Prefix{
				Flags:  t.Flags,
				MaxLen: t.MaxLen,
				ASN:    t.ASN,
				Prefix: t.Prefix,
			}
			c.SendPDU(pdu)
		} else if t.Prefix.Addr().Is4() {
			pdu := &PDUIPv4Prefix{
				Flags:  t.Flags,
				MaxLen: t.MaxLen,
				ASN:    t.ASN,
				Prefix: t.Prefix,
			}
			c.SendPDU(pdu)
		}
	case *BgpsecKey:
		if c.version == 0 || c.dontSendBGPsecKeys {
			return
		}

		pdu := &PDURouterKey{
			Version:              c.version, // The RouterKey PDU is unchanged from rfc8210 to draft-ietf-sidrops-8210bis-10
			Flags:                t.Flags,
			SubjectKeyIdentifier: t.Ski,
			ASN:                  t.ASN,
			SubjectPublicKeyInfo: t.Pubkey,
		}
		c.SendPDU(pdu)
	case *VAP:
		if c.version < 2 || c.dontSendASPA {
			return
		}

		pdu := &PDUASPA{
			Flags:             t.Flags,
			CustomerASNumber:  t.CustomerASN,
			ProviderASNumbers: t.Providers,
		}
		c.SendPDU(pdu)
	}
}

func (c *Client) SendRawPDU(pdu PDU) {
	c.transmits <- pdu
}

func (c *Client) SendPDU(pdu PDU) {
	pdu.SetVersion(c.version)
	c.SendRawPDU(pdu)
}

func (c *Client) Disconnect() {
	if c.log != nil {
		c.log.Infof("Disconnecting client %v", c.String())
	}
	if c.handler != nil {
		c.handler.ClientDisconnected(c)
	}
	c.cancel()
}
