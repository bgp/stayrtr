package main

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bgp/stayrtr/prefixfile"
)

func TestBuildNewVrpMap_expiry(t *testing.T) {
	stuff := testDataFile()
	emptyFile := &prefixfile.RPKIList{
		Metadata:   prefixfile.MetaData{},
		ROA:        []prefixfile.VRPJson{},
		BgpSecKeys: []prefixfile.BgpSecKeyJson{},
	}

	now := time.Now()
	log := log.WithField("client", "TestBuildNewVrpMap_expiry")

	res, inGracePeriod := BuildNewVrpMap(log, make(VRPMap), stuff, now)
	if inGracePeriod != 0 {
		t.Errorf("Initial build does not have objects in grace period")
	}

	_, inGracePeriodPreserved := BuildNewVrpMap(log, res, emptyFile, now.Add(time.Minute*10))
	if inGracePeriodPreserved != len(res) {
		t.Errorf("All objects are in grace period")
	}

	// Objects are kept in grace period
	// 1s before grace period ends
	t1 := now.Add(*GracePeriod).Add(-time.Second * 1)
	res, inGracePeriod = BuildNewVrpMap(log, res, emptyFile, t1)

	assertLastSeenMatchesTimeCount(t, res, t1, 0)
	assertLastSeenMatchesTimeCount(t, res, now, len(stuff.ROA))
	if inGracePeriod != len(stuff.ROA) {
		t.Errorf("All objects should be in grace period. Expected: %d, actual: %d", len(stuff.ROA), inGracePeriod)
	}

	// 1s after grace period ends, they are removed
	res, inGracePeriod = BuildNewVrpMap(log, res, emptyFile, now.Add(*GracePeriod).Add(time.Second*1))
	if len(res) != 0 {
		t.Errorf("Expected no objects to be left after grace period, actual: %d", len(res))
	}
	if inGracePeriod != 0 {
		t.Errorf("Expected 0 objects in grace period, actual: %d", inGracePeriod)
	}
}

func TestBuildNewVrpMap_firsSeen_lastSeen(t *testing.T) {
	t0 := time.Now()
	log := log.WithField("client", "TestBuildNewVrpMap_firstSeen_lastSeen")
	stuff := testDataFile()

	var res, _ = BuildNewVrpMap(log, make(VRPMap), stuff, t0)

	// All have firstSeen + lastSeen equal to t0
	assertFirstSeenMatchesTimeCount(t, res, t0, len(stuff.ROA))
	assertLastSeenMatchesTimeCount(t, res, t0, len(stuff.ROA))
	assertVisibleMatchesTimeCount(t, res, len(stuff.ROA))

	// Supply same data again later
	t1 := t0.Add(time.Minute * 10)
	res, _ = BuildNewVrpMap(log, res, stuff, t1)

	// FirstSeen is constant, LastSeen gets updated, none removed
	assertFirstSeenMatchesTimeCount(t, res, t0, len(stuff.ROA))
	assertLastSeenMatchesTimeCount(t, res, t1, len(stuff.ROA))
	assertVisibleMatchesTimeCount(t, res, len(stuff.ROA))

	// Supply one new VRP, expect one at new time, others at old time
	otherStuff := []prefixfile.VRPJson{
		{
			Prefix: "2001:DB8::/32",
			Length: 48,
			ASN:    65536,
			TA:     "testrir",
		},
	}
	otherStuffFile := prefixfile.RPKIList{
		Metadata:   prefixfile.MetaData{},
		ROA:        otherStuff,
		BgpSecKeys: []prefixfile.BgpSecKeyJson{},
	}
	t2 := t1.Add(time.Minute * 10)
	res, _ = BuildNewVrpMap(log, res, &otherStuffFile, t2)

	// LastSeen gets updated just for the new item
	assertFirstSeenMatchesTimeCount(t, res, t0, len(stuff.ROA))
	assertLastSeenMatchesTimeCount(t, res, t1, len(stuff.ROA))

	assertFirstSeenMatchesTimeCount(t, res, t2, len(otherStuff))
	assertLastSeenMatchesTimeCount(t, res, t2, len(otherStuff))
	assertVisibleMatchesTimeCount(t, res, len(otherStuff))
}

func assertFirstSeenMatchesTimeCount(t *testing.T, vrps VRPMap, pit time.Time, expected int) {
	actual := countMatches(vrps, func(vrp *VRPJsonSimple) bool { return vrp.FirstSeen == pit.Unix() })
	if actual != expected {
		t.Errorf("Expected %d VRPs to have FirstSeen of %v, actual: %d", expected, pit, actual)
	}
}

func assertLastSeenMatchesTimeCount(t *testing.T, vrps VRPMap, pit time.Time, expected int) {
	actual := countMatches(vrps, func(vrp *VRPJsonSimple) bool { return vrp.LastSeen == pit.Unix() })
	if actual != expected {
		t.Errorf("Expected %d VRPs to have LastSeen of %v, actual: %d", expected, pit, actual)
	}
}

func assertVisibleMatchesTimeCount(t *testing.T, vrps VRPMap, expected int) {
	actual := countMatches(vrps, func(vrp *VRPJsonSimple) bool { return vrp.Visible })
	if actual != expected {
		t.Errorf("Expected %d VRPs to be visible, actual: %d", expected, actual)
	}
}

type extractor func(object *VRPJsonSimple) bool

func countMatches(vrps VRPMap, e extractor) int {
	matches := 0
	for _, entry := range vrps {
		if e(entry) {
			matches++
		}
	}

	return matches
}

func testData() []prefixfile.VRPJson {
	var stuff []prefixfile.VRPJson
	stuff = append(stuff,
		prefixfile.VRPJson{
			Prefix: "192.168.0.0/24",
			Length: 24,
			ASN:    65537,
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "192.168.0.0/24",
			Length: 24,
			ASN:    65536,
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "2001:db8::/32",
			Length: 33,
			ASN:    "AS64496",
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 25,
			ASN:    64497,
			TA:     "testrir",
		},
	)

	return stuff
}

func testDataFile() *prefixfile.RPKIList {
	stuff := prefixfile.RPKIList{
		Metadata:   prefixfile.MetaData{},
		ROA:        testData(),
		BgpSecKeys: []prefixfile.BgpSecKeyJson{},
	}
	return &stuff
}
