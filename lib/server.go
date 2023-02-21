package rtrlib

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func GenerateSessionId() uint16 {
	var sessid uint16
	r := rand.New(rand.NewSource(time.Now().UTC().Unix()))
	sessid = uint16(r.Uint32())
	return sessid
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

type VRPManager interface {
	GetCurrentSerial(uint16) (uint32, bool)
	GetSessionId() uint16
	GetCurrentVRPs() ([]VRP, bool)
	GetCurrentKeys() ([]BgpSecKey, bool)
	GetVRPsSerialDiff(uint32) ([]VRP, bool)
	GetKeysSerialDiff(uint32) ([]BgpSecKey, bool)
}

type DefaultRTREventHandler struct {
	vrpManager VRPManager
	Log        Logger
}

func (e *DefaultRTREventHandler) SetVRPManager(m VRPManager) {
	e.vrpManager = m
}

func (e *DefaultRTREventHandler) RequestCache(c *Client) {
	if e.Log != nil {
		e.Log.Debugf("%v > Request Cache", c)
	}
	sessionId := e.vrpManager.GetSessionId()
	serial, valid := e.vrpManager.GetCurrentSerial(sessionId)
	if !valid {
		c.SendNoDataError()
		if e.Log != nil {
			e.Log.Debugf("%v < No data", c)
		}
	} else {
		vrps, exists := e.vrpManager.GetCurrentVRPs()
		keys, _ := e.vrpManager.GetCurrentKeys()
		if !exists {
			c.SendInternalError()
			if e.Log != nil {
				e.Log.Debugf("%v < Internal error requesting cache (does not exists)", c)
			}
		} else {
			c.SendClientData(sessionId, serial, vrps, keys)
			if e.Log != nil {
				e.Log.Debugf("%v < Sent VRPs (current serial %d, session: %d)", c, serial, sessionId)
			}
		}
	}
}

func (e *DefaultRTREventHandler) RequestNewVersion(c *Client, sessionId uint16, serialNumber uint32) {
	if e.Log != nil {
		e.Log.Debugf("%v > Request New Version", c)
	}
	server_SessionId := e.vrpManager.GetSessionId()
	if sessionId != server_SessionId {
		c.SendCorruptData()
		if e.Log != nil {
			e.Log.Debugf("%v < Invalid request (client asked for session %d but server is at %d)", c, sessionId, server_SessionId)
		}
		c.Disconnect()
		return
	}
	serial, valid := e.vrpManager.GetCurrentSerial(sessionId)
	if !valid {
		c.SendNoDataError()
		if e.Log != nil {
			e.Log.Debugf("%v < No data", c)
		}
	} else {
		vrps, exists := e.vrpManager.GetVRPsSerialDiff(serialNumber)
		keys, _ := e.vrpManager.GetKeysSerialDiff(serialNumber)
		if !exists {
			c.SendCacheReset()
			if e.Log != nil {
				e.Log.Debugf("%v < Sent cache reset", c)
			}
		} else {
			c.SendClientData(sessionId, serial, vrps, keys)
			if e.Log != nil {
				e.Log.Debugf("%v < Sent VRPs (current serial %d, session from client: %d)", c, serial, sessionId)
			}
		}
	}
}

type Server struct {
	baseVersion uint8
	clientlock  *sync.RWMutex
	clients     []*Client
	sessId      uint16
	connected   int
	maxconn     int

	sshconfig *ssh.ServerConfig

	handler        RTRServerEventHandler
	simpleHandler  RTREventHandler
	enforceVersion bool

	vrplock          *sync.RWMutex
	vrpListDiff      [][]VRP
	vrpMapSerial     map[uint32]int
	vrpListSerial    []uint32
	vrpCurrent       []VRP
	vrpCurrentSerial uint32
	bgpSecListDiff   [][]BgpSecKey
	bgpSecMapSerial  map[uint32]int
	bgpSecListSerial []uint32
	bgpSecCurrent    []BgpSecKey

	keepDiff     int
	manualserial bool

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

	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32

	Log        Logger
	LogVerbose bool
}

func NewServer(configuration ServerConfiguration, handler RTRServerEventHandler, simpleHandler RTREventHandler) *Server {
	sessid := GenerateSessionId()

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
		vrplock:       &sync.RWMutex{},
		vrpListDiff:   make([][]VRP, 0),
		vrpMapSerial:  make(map[uint32]int),
		vrpListSerial: make([]uint32, 0),
		vrpCurrent:    make([]VRP, 0),
		keepDiff:      configuration.KeepDifference,

		bgpSecListDiff:   make([][]BgpSecKey, 0),
		bgpSecMapSerial:  make(map[uint32]int),
		bgpSecListSerial: make([]uint32, 0),
		bgpSecCurrent:    make([]BgpSecKey, 0),

		clientlock:     &sync.RWMutex{},
		clients:        make([]*Client, 0),
		sessId:         sessid,
		maxconn:        configuration.MaxConn,
		baseVersion:    configuration.ProtocolVersion,
		enforceVersion: configuration.EnforceVersion,
		handler:        handler,
		simpleHandler:  simpleHandler,

		pduRefreshInterval: refreshInterval,
		pduRetryInterval:   retryInterval,
		pduExpireInterval:  expireInterval,

		log:        configuration.Log,
		logverbose: configuration.LogVerbose,
	}
}

func (vrp VRP) HashKey() string {
	return fmt.Sprintf("%v-%v-%v", vrp.Prefix.String(), vrp.MaxLen, vrp.ASN)
}

func ConvertVRPListToMap(vrps []VRP) map[string]VRP {
	vrpMap := make(map[string]VRP, len(vrps))
	for _, v := range vrps {
		vrpMap[v.HashKey()] = v
	}
	return vrpMap
}

func ComputeVRPDiff(newVrps []VRP, prevVrps []VRP) (added, removed, unchanged []VRP) {
	added = make([]VRP, 0)
	removed = make([]VRP, 0)
	unchanged = make([]VRP, 0)

	newVrpsMap := ConvertVRPListToMap(newVrps)
	prevVrpsMap := ConvertVRPListToMap(prevVrps)

	for _, vrp := range newVrps {
		_, exists := prevVrpsMap[vrp.HashKey()]
		if !exists {
			rcopy := vrp.Copy()
			rcopy.Flags = 1
			added = append(added, rcopy)
		}
	}
	for _, vrp := range prevVrps {
		_, exists := newVrpsMap[vrp.HashKey()]
		if !exists {
			rcopy := vrp.Copy()
			rcopy.Flags = 0
			removed = append(removed, rcopy)
		} else {
			rcopy := vrp.Copy()
			unchanged = append(unchanged, rcopy)
		}
	}

	return added, removed, unchanged
}

func ApplyVRPDiff(diff []VRP, prevVrps []VRP) []VRP {
	newvrps := make([]VRP, 0)
	diffMap := ConvertVRPListToMap(diff)
	prevVrpsMap := ConvertVRPListToMap(prevVrps)

	for _, vrp := range prevVrps {
		_, exists := diffMap[vrp.HashKey()]
		if !exists {
			rcopy := vrp.Copy()
			newvrps = append(newvrps, rcopy)
		}
	}
	for _, vrp := range diff {
		if vrp.Flags == FLAG_ADDED {
			rcopy := vrp.Copy()
			newvrps = append(newvrps, rcopy)
		} else if vrp.Flags == FLAG_REMOVED {
			cvrp, exists := prevVrpsMap[vrp.HashKey()]
			if !exists {
				rcopy := vrp.Copy()
				newvrps = append(newvrps, rcopy)
			} else {
				if cvrp.Flags == FLAG_REMOVED {
					rcopy := vrp.Copy()
					newvrps = append(newvrps, rcopy)
				}
			}
		}

	}
	return newvrps
}

func ConvertBGPSecKeyListToMap(keys []BgpSecKey) map[string]BgpSecKey {
	keyMap := make(map[string]BgpSecKey, len(keys))
	for _, v := range keys {
		keyMap[v.HashKey()] = v
	}
	return keyMap
}

func ComputeBGPSecKeyDiff(newKeys, preKeys []BgpSecKey) (added, removed, unchanged []BgpSecKey) {
	added = make([]BgpSecKey, 0)
	removed = make([]BgpSecKey, 0)
	unchanged = make([]BgpSecKey, 0)

	newKeysMap := ConvertBGPSecKeyListToMap(newKeys)
	prevKeysMap := ConvertBGPSecKeyListToMap(preKeys)

	for _, vrp := range newKeys {
		_, exists := prevKeysMap[vrp.HashKey()]
		if !exists {
			rcopy := vrp.Copy()
			rcopy.Flags = 1
			added = append(added, rcopy)
		}
	}
	for _, vrp := range preKeys {
		_, exists := newKeysMap[vrp.HashKey()]
		if !exists {
			rcopy := vrp.Copy()
			rcopy.Flags = 0
			removed = append(removed, rcopy)
		} else {
			rcopy := vrp.Copy()
			unchanged = append(unchanged, rcopy)
		}
	}

	return added, removed, unchanged
}

func ApplyBGPSecKeyDiff(diff, prevKeys []BgpSecKey) []BgpSecKey {
	newkeys := make([]BgpSecKey, 0)
	diffMap := ConvertBGPSecKeyListToMap(diff)
	prevkeysMap := ConvertBGPSecKeyListToMap(prevKeys)

	for _, key := range prevKeys {
		_, exists := diffMap[key.HashKey()]
		if !exists {
			rcopy := key.Copy()
			newkeys = append(newkeys, rcopy)
		}
	}
	for _, key := range diff {
		if key.Flags == FLAG_ADDED {
			rcopy := key.Copy()
			newkeys = append(newkeys, rcopy)
		} else if key.Flags == FLAG_REMOVED {
			cvrp, exists := prevkeysMap[key.HashKey()]
			if !exists {
				rcopy := key.Copy()
				newkeys = append(newkeys, rcopy)
			} else {
				if cvrp.Flags == FLAG_REMOVED {
					rcopy := key.Copy()
					newkeys = append(newkeys, rcopy)
				}
			}
		}

	}
	return newkeys
}

func (s *Server) SetManualSerial(v bool) {
	s.manualserial = v
}

func (s *Server) GetSessionId() uint16 {
	return s.sessId
}

func (s *Server) GetCurrentVRPs() ([]VRP, bool) {
	s.vrplock.RLock()
	vrp := s.vrpCurrent
	s.vrplock.RUnlock()
	return vrp, true
}

func (s *Server) GetCurrentKeys() ([]BgpSecKey, bool) {
	s.vrplock.RLock()
	keys := s.bgpSecCurrent
	s.vrplock.RUnlock()
	return keys, true
}

func (s *Server) GetVRPsSerialDiff(serial uint32) ([]VRP, bool) {
	s.vrplock.RLock()
	vrp, ok := s.getVRPsSerialDiff(serial)
	s.vrplock.RUnlock()
	return vrp, ok
}

func (s *Server) getVRPsSerialDiff(serial uint32) ([]VRP, bool) {
	if serial == s.vrpCurrentSerial {
		return []VRP{}, true
	}

	vrp := make([]VRP, 0)
	index, ok := s.vrpMapSerial[serial]
	if ok {
		vrp = s.vrpListDiff[index]
	}
	return vrp, ok
}

func (s *Server) GetKeysSerialDiff(serial uint32) ([]BgpSecKey, bool) {
	if serial == s.vrpCurrentSerial {
		return []BgpSecKey{}, true
	}

	keys := make([]BgpSecKey, 0)
	index, ok := s.bgpSecMapSerial[serial]
	if ok {
		keys = s.bgpSecListDiff[index]
	}
	return keys, ok
}

func (s *Server) GetCurrentSerial(sessId uint16) (uint32, bool) {
	s.vrplock.RLock()
	serial, valid := s.getCurrentSerial()
	s.vrplock.RUnlock()
	return serial, valid
}

func (s *Server) getCurrentSerial() (uint32, bool) {
	return s.vrpCurrentSerial, len(s.vrpListSerial) > 0
}

func (s *Server) GenerateSerial() uint32 {
	s.vrplock.RLock()
	newserial := s.generateSerial()
	s.vrplock.RUnlock()
	return newserial
}

func (s *Server) generateSerial() uint32 {
	newserial := s.vrpCurrentSerial
	if !s.manualserial && len(s.vrpListSerial) > 0 {
		newserial = s.vrpListSerial[len(s.vrpListSerial)-1] + 1
	}
	return newserial
}

func (s *Server) setSerial(serial uint32) {
	s.vrpCurrentSerial = serial
}

// This function sets the serial. Function must
// be called before the VRPs data is added.
func (s *Server) SetSerial(serial uint32) {
	s.vrplock.RLock()
	defer s.vrplock.RUnlock()
	//s.vrpListSerial = make([]uint32, 0)
	s.setSerial(serial)
}

func (s *Server) CountVRPs() int {
	s.vrplock.RLock()
	defer s.vrplock.RUnlock()

	return len(s.vrpCurrent)
}

func (s *Server) AddVRPsAndKeys(vrps []VRP, keys []BgpSecKey) {
	s.vrplock.RLock()
	vrpCurrent := s.vrpCurrent
	keyCurrent := s.bgpSecCurrent

	addedVRP, removedVRP, unchangedVRP := ComputeVRPDiff(vrps, vrpCurrent)
	if s.log != nil && s.logverbose {
		s.log.Debugf("Computed VRP diff: added (%v), removed (%v), unchanged (%v)", addedVRP, removedVRP, unchangedVRP)
	} else if s.log != nil {
		s.log.Debugf("Computed VRP diff: added (%d), removed (%d), unchanged (%d)", len(addedVRP), len(removedVRP), len(unchangedVRP))
	}
	curVRPDiff := append(addedVRP, removedVRP...)

	addedKeys, removedKeys, unchangedKeys := ComputeBGPSecKeyDiff(keys, keyCurrent)
	if s.log != nil && s.logverbose {
		s.log.Debugf("Computed BGPsec diff: added (%v), removed (%v), unchanged (%v)", addedKeys, removedKeys, unchangedKeys)
	} else if s.log != nil {
		s.log.Debugf("Computed BGPsec diff: added (%d), removed (%d), unchanged (%d)", len(addedKeys), len(removedKeys), len(unchangedKeys))
	}
	curKeyDiff := append(addedKeys, removedKeys...)
	s.vrplock.RUnlock()

	s.AddDataDiff(curVRPDiff, curKeyDiff)
}

func (s *Server) addSerial(serial uint32) []uint32 {
	removed := make([]uint32, 0)
	if len(s.vrpListSerial) >= s.keepDiff && s.keepDiff > 0 {
		removeDiff := len(s.vrpListSerial) - s.keepDiff
		removed = s.vrpListSerial[0:removeDiff]
		s.vrpListSerial = s.vrpListSerial[removeDiff:]
	}
	s.vrpListSerial = append(s.vrpListSerial, serial)
	return removed
}

func (s *Server) AddDataDiff(diffVRP []VRP, diffKeys []BgpSecKey) {
	// Only do a write lock while we read some basic data and make
	// diffs.
	s.vrplock.RLock()
	nextVRPDiff := make([][]VRP, len(s.vrpListDiff))
	nextKeysDiff := make([][]BgpSecKey, len(s.bgpSecListDiff))
	for i, prevVrps := range s.vrpListDiff {
		nextVRPDiff[i] = ApplyVRPDiff(diffVRP, prevVrps)
	}
	for i, prevKeys := range s.bgpSecListDiff {
		nextKeysDiff[i] = ApplyBGPSecKeyDiff(diffKeys, prevKeys)
	}
	newVrpCurrent := ApplyVRPDiff(diffVRP, s.vrpCurrent)
	newBgpSecCurrent := ApplyBGPSecKeyDiff(diffKeys, s.bgpSecCurrent)
	curserial, _ := s.getCurrentSerial()
	s.vrplock.RUnlock()
	// Now we have the needed starting data, we can read lock too
	s.vrplock.Lock()
	defer s.vrplock.Unlock()
	newserial := s.generateSerial()
	removed := s.addSerial(newserial)

	nextVRPDiff = append(nextVRPDiff, diffVRP)
	nextKeysDiff = append(nextKeysDiff, diffKeys)
	if (len(nextVRPDiff)+len(nextKeysDiff)) >= s.keepDiff && s.keepDiff > 0 {
		nextVRPDiff = nextVRPDiff[len(removed):]
		nextKeysDiff = nextKeysDiff[len(removed):]
	}
	s.vrpMapSerial[curserial] = len(nextVRPDiff) - 1
	s.bgpSecMapSerial[curserial] = len(nextKeysDiff) - 1

	if len(removed) > 0 {
		for k, v := range s.vrpMapSerial {
			if k != curserial {
				s.vrpMapSerial[k] = v - len(removed)
			}
		}
		for k, v := range s.bgpSecMapSerial {
			if k != curserial {
				s.bgpSecMapSerial[k] = v - len(removed)
			}
		}
	}

	for _, removeSerial := range removed {
		delete(s.vrpMapSerial, removeSerial)
		delete(s.bgpSecMapSerial, removeSerial)
	}

	s.vrpListDiff = nextVRPDiff
	s.vrpCurrent = newVrpCurrent
	s.bgpSecListDiff = nextKeysDiff
	s.bgpSecCurrent = newBgpSecCurrent
	s.setSerial(newserial)
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

func (s *Server) SetSessionId(sessId uint16) {
	s.sessId = sessId
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
	client := ClientFromConn(tcpconn, s, s)
	client.log = s.log
	if s.enforceVersion {
		client.SetVersion(s.baseVersion)
	}
	client.SetIntervals(s.pduRefreshInterval, s.pduRetryInterval, s.pduExpireInterval)
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
	for i, c := range s.clients {
		list[i] = c
	}
	s.clientlock.RUnlock()
	return list
}

func (s *Server) NotifyClientsLatest() {
	serial, _ := s.GetCurrentSerial(s.sessId)
	s.NotifyClients(serial)
}

func (s *Server) NotifyClients(serialNumber uint32) {
	clients := s.GetClientList()
	for _, c := range clients {
		c.Notify(s.sessId, serialNumber)
	}
}

func (s *Server) SendPDU(pdu PDU) {
	for _, client := range s.clients {
		client.SendPDU(pdu)
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
		quit:          make(chan bool),
	}
}

func ClientFromConnSSH(tcpconn net.Conn, channel ssh.Channel, handler RTRServerEventHandler, simpleHandler RTREventHandler) *Client {
	client := ClientFromConn(tcpconn, handler, simpleHandler)
	client.rd = channel
	client.wr = channel
	return client
}

type Client struct {
	connected     bool
	version       uint8
	versionset    bool
	tcpconn       net.Conn
	rd            io.Reader
	wr            io.Writer
	handler       RTRServerEventHandler
	simpleHandler RTREventHandler
	curserial     uint32

	transmits chan PDU
	quit      chan bool

	enforceVersion      bool
	disableVersionCheck bool
	doNotSendBGPSEC     bool

	refreshInterval uint32
	retryInterval   uint32
	expireInterval  uint32

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

func (c *Client) checkVersion(newversion uint8) {
	if (!c.versionset || newversion == c.version) && (newversion == PROTOCOL_VERSION_1 || newversion == PROTOCOL_VERSION_0) {
		c.SetVersion(newversion)
	} else {
		if c.log != nil {
			c.log.Debugf("%v: has bad version (received: v%v, current: v%v) error", c.String(), newversion, c.version)
		}
		c.SendWrongVersionError()
		c.Disconnect()
	}
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

func (c *Client) sendLoop() {
	for c.connected {
		select {
		case pdu := <-c.transmits:
			c.wr.Write(pdu.Bytes())
		case <-c.quit:
			goto abort
		}
	}
abort:
}

func (c *Client) Start() {
	c.connected = true
	if c.handler != nil {
		c.handler.ClientConnected(c)
	}

	go c.sendLoop()

	buf := make([]byte, 8000)
	for c.connected {
		// Remove this?
		length, err := c.rd.Read(buf)
		if err != nil || length == 0 {
			if c.log != nil {
				c.log.Debugf("Error %v", err)
			}
			c.Disconnect()
			return
		}

		pkt := buf[0:length]
		dec, err := DecodeBytes(pkt)
		if err != nil || dec == nil {
			if c.log != nil {
				c.log.Errorf("Error %v", err)
			}
			c.Disconnect()
			continue
		}
		if !c.disableVersionCheck {
			c.checkVersion(dec.GetVersion())
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

func (c *Client) Notify(sessionId uint16, serialNumber uint32) {
	pdu := &PDUSerialNotify{
		SessionId:    sessionId,
		SerialNumber: serialNumber,
	}
	c.SendPDU(pdu)
}

type BgpSecKey struct {
	ASN    uint32
	Pubkey []byte
	Ski    []byte
	Flags  uint8
}

func (r BgpSecKey) HashKey() string {
	return fmt.Sprintf("%v-%v-%v", r.ASN, r.Ski, r.Pubkey)
}

func (r BgpSecKey) String() string {
	return fmt.Sprintf("BgpSecKey %x -> AS%v, Flags: %v", r.Ski, r.ASN, r.Flags)
}

func (r1 BgpSecKey) Equals(r2 BgpSecKey) bool {
	return r1.ASN == r2.ASN && bytes.Equal(r1.Ski, r2.Ski) && bytes.Equal(r1.Pubkey, r2.Pubkey)
}

func (r1 BgpSecKey) Copy() BgpSecKey {
	newBgpSecKey := BgpSecKey{
		ASN:    r1.ASN,
		Pubkey: make([]byte, len(r1.Pubkey)),
		Ski:    make([]byte, len(r1.Ski)),
		Flags:  r1.Flags,
	}
	copy(newBgpSecKey.Pubkey, r1.Pubkey)
	copy(newBgpSecKey.Ski, r1.Ski)
	return newBgpSecKey
}

type VRP struct {
	Prefix net.IPNet
	MaxLen uint8
	ASN    uint32
	Flags  uint8
}

func (r VRP) String() string {
	return fmt.Sprintf("VRP %v -> /%v, AS%v, Flags: %v", r.Prefix.String(), r.MaxLen, r.ASN, r.Flags)
}

func (r1 VRP) Equals(r2 VRP) bool {
	return r1.MaxLen == r2.MaxLen && r1.ASN == r2.ASN && r1.Prefix.IP.Equal(r2.Prefix.IP) && bytes.Equal(r1.Prefix.Mask, r2.Prefix.Mask)
}

func (r1 VRP) Copy() VRP {
	newprefix := net.IPNet{
		IP:   make([]byte, len(r1.Prefix.IP)),
		Mask: make([]byte, len(r1.Prefix.Mask)),
	}
	copy(newprefix.IP, r1.Prefix.IP)
	copy(newprefix.Mask, r1.Prefix.Mask)
	return VRP{
		Prefix: newprefix,
		ASN:    r1.ASN,
		MaxLen: r1.MaxLen,
		Flags:  r1.Flags}
}

func (c *Client) SendClientData(sessionId uint16, serialNumber uint32, vrps []VRP, bgpSecKeys []BgpSecKey) {
	pduBegin := &PDUCacheResponse{
		SessionId: sessionId,
	}
	c.SendPDU(pduBegin)
	for _, vrp := range vrps {
		c.SendVRP(vrp)
	}
	for _, key := range bgpSecKeys {
		c.SendBGPSecKey(key)
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

func (c *Client) SendVRP(vrp VRP) {
	if vrp.Prefix.IP.To4() == nil && vrp.Prefix.IP.To16() != nil {
		pdu := &PDUIPv6Prefix{
			Flags:  vrp.Flags,
			MaxLen: vrp.MaxLen,
			ASN:    vrp.ASN,
			Prefix: vrp.Prefix,
		}
		c.SendPDU(pdu)
	} else if vrp.Prefix.IP.To4() != nil {
		pdu := &PDUIPv4Prefix{
			Flags:  vrp.Flags,
			MaxLen: vrp.MaxLen,
			ASN:    vrp.ASN,
			Prefix: vrp.Prefix,
		}
		c.SendPDU(pdu)
	}
}

func (c *Client) SendBGPSecKey(key BgpSecKey) {
	if c.version == 0 {
		// Do not allow router keys to be send on a version that does not support it
		return
	}
	if c.doNotSendBGPSEC {
		return
	}

	pdu := &PDURouterKey{
		Version:              1,
		Flags:                key.Flags,
		SubjectKeyIdentifier: key.Ski,
		ASN:                  key.ASN,
		SubjectPublicKeyInfo: key.Pubkey,
	}
	c.SendPDU(pdu)
}

func (c *Client) SendRawPDU(pdu PDU) {
	c.transmits <- pdu
}

func (c *Client) SendPDU(pdu PDU) {
	pdu.SetVersion(c.version)
	c.SendRawPDU(pdu)
}

func (c *Client) Disconnect() {
	c.connected = false
	if c.log != nil {
		c.log.Infof("Disconnecting client %v", c.String())
	}
	if c.handler != nil {
		c.handler.ClientDisconnected(c)
	}
	select {
	case c.quit <- true:
	default:
	}

	c.tcpconn.Close()
}
