package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/metrics"
	log "github.com/sirupsen/logrus"
)

type VRPCache struct {
	lastdata   *VRPList
	lasthash   []byte
	lastchange time.Time
	lastts     time.Time
	sendNotifs bool
	useSerial  int
	cacheBin   string

	FetchConfig *FetchConfig

	Server *rtr.Server

	metricsEvent *metrics.MetricsEvent // this is busted. Fix me.

	exported VRPList
	mu       *sync.RWMutex

	slurm *SlurmConfig

	checktime bool
}

func NewVRPCache(server *rtr.Server, checktime bool, sendNotifs bool) *VRPCache {
	c := &VRPCache{
		Server:      server,
		FetchConfig: NewFetchConfig(),
		lastdata:    &VRPList{},
		sendNotifs:  sendNotifs,
		checktime:   checktime,
	}
	return c
}

// newSHA256 will return the sha256 sum of the byte slice
// The return will be converted form a [32]byte to []byte
func newSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func decodeJSON(data []byte) (*VRPList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var vrplistjson VRPList
	err := dec.Decode(&vrplistjson)
	return &vrplistjson, err
}

func isValidPrefixLength(prefix *net.IPNet, maxLength uint8) bool {
	plen, max := net.IPMask.Size(prefix.Mask)

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
// Will return a deduped slice, as well as total VRPs, IPv4 VRPs, and IPv6 VRPs
func processData(vrplistjson []VRPJson) ([]rtr.VRP, int, int, int) {
	filterDuplicates := make(map[string]bool)

	var vrplist []rtr.VRP
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

		if prefix.IP.To4() != nil {
			countv4++
		} else {
			countv6++
		}

		key := fmt.Sprintf("%s,%d,%d", prefix, asn, v.Length)
		_, exists := filterDuplicates[key]
		if exists {
			continue
		}
		filterDuplicates[key] = true

		vrp := rtr.VRP{
			Prefix: *prefix,
			ASN:    asn,
			MaxLen: v.Length,
		}
		vrplist = append(vrplist, vrp)
	}
	return vrplist, countv4 + countv6, countv4, countv6
}

type IdenticalFile struct {
	File string
}

func (e IdenticalFile) Error() string {
	return fmt.Sprintf("File %s is identical to the previous version", e.File)
}

func (c *VRPCache) Exporter(wr http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	toExport := c.exported
	c.mu.RUnlock()
	enc := json.NewEncoder(wr)
	enc.Encode(toExport)
}

// Update the state based on the current slurm file and data.
func (c *VRPCache) UpdateFromNewState() error {
	sessid := c.Server.GetSessionId()

	if c.checktime {
		buildtime, err := time.Parse(time.RFC3339, c.lastdata.Metadata.Buildtime)
		if err != nil {
			return err
		}
		notafter := buildtime.Add(time.Hour * 24)
		if time.Now().UTC().After(notafter) {
			return errors.New(fmt.Sprintf("VRP JSON file is older than 24 hours: %v", buildtime))
		}
	}

	vrpsjson := c.lastdata.Data
	if c.slurm != nil {
		kept, removed := c.slurm.FilterOnVRPs(vrpsjson)
		asserted := c.slurm.AssertVRPs()
		log.Infof("Slurm filtering: %v kept, %v removed, %v asserted", len(kept), len(removed), len(asserted))
		vrpsjson = append(kept, asserted...)
	}

	vrps, count, countv4, countv6 := processData(vrpsjson)

	log.Infof("New update (%v uniques, %v total prefixes).", len(vrps), count)

	c.Server.AddVRPs(vrps)

	serial, _ := c.Server.GetCurrentSerial(sessid)
	log.Infof("Updated added, new serial %v", serial)
	if c.sendNotifs {
		log.Debugf("Sending notifications to clients")
		c.Server.NotifyClientsLatest()
	}

	c.mu.Lock()
	c.exported = VRPList{
		Metadata: MetaData{
			Counts:    len(vrpsjson),
			Buildtime: c.lastdata.Metadata.Buildtime,
		},
		Data: vrpsjson,
	}

	c.mu.Unlock()

	if c.metricsEvent != nil {
		var countv4_dup int
		var countv6_dup int
		for _, vrp := range vrps {
			if vrp.Prefix.IP.To4() != nil {
				countv4_dup++
			} else if vrp.Prefix.IP.To16() != nil {
				countv6_dup++
			}
		}
		c.metricsEvent.UpdateMetrics(countv4, countv6, countv4_dup, countv6_dup, c.lastchange, c.lastts, c.cacheBin)
	}

	return nil
}

func (c *VRPCache) UpdateFile(file string) (bool, error) {
	log.Debugf("Refreshing cache from %s", file)

	c.lastts = time.Now().UTC()
	data, code, lastrefresh, err := c.FetchConfig.FetchFile(file)
	if err != nil {
		return false, err
	}
	if lastrefresh {
		metrics.LastRefresh.WithLabelValues(file).Set(float64(c.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		metrics.RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	hsum := newSHA256(data)
	if c.lasthash != nil {
		cres := bytes.Compare(c.lasthash, hsum)
		if cres == 0 {
			return false, IdenticalFile{File: file}
		}
	}

	log.Infof("new cache file: Updating sha256 hash %x -> %x", c.lasthash, hsum)

	vrplistjson, err := decodeJSON(data)
	if err != nil {
		return false, err
	}

	c.lasthash = hsum
	c.lastchange = time.Now().UTC()
	c.lastdata = vrplistjson

	return true, nil
}

func (c *VRPCache) UpdateSlurm(file string) (bool, error) {
	log.Debugf("Refreshing slurm from %v", file)
	data, code, lastrefresh, err := c.FetchConfig.FetchFile(file)
	if err != nil {
		return false, err
	}
	if lastrefresh {
		metrics.LastRefresh.WithLabelValues(file).Set(float64(c.lastts.UnixNano() / 1e9))
	}
	if code != -1 {
		metrics.RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", code)).Inc()
	}

	buf := bytes.NewBuffer(data)

	slurm, err := DecodeJSONSlurm(buf)
	if err != nil {
		return false, err
	}
	c.slurm = slurm
	return true, nil
}

func (c *VRPCache) RoutineUpdate(file string, interval int, slurmFile string) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs, slurm: %v)", file, interval, slurmFile)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		var delay *time.Timer
		if c.lastchange.IsZero() {
			log.Warn("Initial sync not complete. Refreshing every 30 seconds")
			delay = time.NewTimer(time.Duration(30) * time.Second)
		} else {
			delay = time.NewTimer(time.Duration(interval) * time.Second)
		}
		select {
		case <-delay.C:
		case <-signals:
			log.Debug("Received HUP signal")
		}
		delay.Stop()
		slurmNotPresentOrUpdated := false
		if slurmFile != "" {
			var err error
			slurmNotPresentOrUpdated, err = c.UpdateSlurm(slurmFile)
			if err != nil {
				switch err.(type) {
				case HttpNotModified:
					log.Info(err)
				case IdenticalEtag:
					log.Info(err)
				default:
					log.Errorf("Slurm: %v", err)
				}
			}
		}
		cacheUpdated, err := c.UpdateFile(file)
		if err != nil {
			switch err.(type) {
			case HttpNotModified:
				log.Info(err)
			case IdenticalEtag:
				log.Info(err)
			case IdenticalFile:
				log.Info(err)
			default:
				log.Errorf("Error updating: %v", err)
			}
		}

		// Only process the first time after there is either a cache or SLURM
		// update.
		if cacheUpdated || slurmNotPresentOrUpdated {
			err := c.UpdateFromNewState()
			if err != nil {
				log.Errorf("Error updating from new state: %v", err)
			}
		}
	}
}
