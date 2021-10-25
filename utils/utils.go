package utils

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type FetchConfig struct {
	UserAgent string
	Mime      string

	etags                  map[string]string
	lastModified           map[string]time.Time
	conditionalRequestLock *sync.RWMutex
	EnableEtags            bool
	EnableLastModified     bool
}

func NewFetchConfig() *FetchConfig {
	return &FetchConfig{
		etags:                  make(map[string]string),
		lastModified:           make(map[string]time.Time),
		conditionalRequestLock: &sync.RWMutex{},
		Mime:                   "application/json",
	}
}

type HttpNotModified struct {
	File string
}

func (e HttpNotModified) Error() string {
	return fmt.Sprintf("HTTP 304 Not modified for %s", e.File)
}

type IdenticalEtag struct {
	File string
	Etag string
}

func (e IdenticalEtag) Error() string {
	return fmt.Sprintf("File %s is identical according to Etag: %s", e.File, e.Etag)
}

func (c *FetchConfig) FetchFile(file string) ([]byte, int, bool, error) {
	var f io.Reader
	var err error
	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {

		// Copying base of DefaultTransport from https://golang.org/src/net/http/transport.go
		// There is a proposal for a Clone of
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ProxyConnectHeader:    map[string][]string{},
		}
		// Keep User-Agent in proxy request
		tr.ProxyConnectHeader.Set("User-Agent", c.UserAgent)

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", file, nil)
		if err != nil {
			return nil, -1, false, err
		}

		req.Header.Set("User-Agent", c.UserAgent)
		if c.Mime != "" {
			req.Header.Set("Accept", c.Mime)
		}

		c.conditionalRequestLock.RLock()
		if c.EnableEtags {
			etag, ok := c.etags[file]
			if ok {
				req.Header.Set("If-None-Match", etag)
			}
		}
		if c.EnableLastModified {
			lastModified, ok := c.lastModified[file]
			if ok {
				req.Header.Set("If-Modified-Since", lastModified.UTC().Format(http.TimeFormat))
			}
		}
		c.conditionalRequestLock.RUnlock()

		proxyurl, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, -1, false, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		if err != nil {
			return nil, -1, false, err
		}

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, -1, false, err
		}
		if fhttp.Body != nil {
			defer fhttp.Body.Close()
		}
		defer client.CloseIdleConnections()
		//RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", fhttp.StatusCode)).Inc()

		if fhttp.StatusCode == 304 {
			//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
			return nil, fhttp.StatusCode, true, HttpNotModified{
				File: file,
			}
		} else if fhttp.StatusCode != 200 {
			c.conditionalRequestLock.Lock()
			delete(c.etags, file)
			delete(c.lastModified, file)
			c.conditionalRequestLock.Unlock()
			return nil, fhttp.StatusCode, true, fmt.Errorf("HTTP %s", fhttp.Status)
		}
		//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))

		f = fhttp.Body

		newEtag := fhttp.Header.Get("ETag")

		if !c.EnableEtags || newEtag == "" || newEtag != c.etags[file] { // check lock here
			c.conditionalRequestLock.Lock()
			c.etags[file] = newEtag
			c.conditionalRequestLock.Unlock()
		} else {
			return nil, fhttp.StatusCode, true, IdenticalEtag{
				File: file,
				Etag: newEtag,
			}
		}

		if c.EnableLastModified {
			// Accept any valid Last-Modified values. Because of the 1s resolution,
			// getting the same value is not an error (c.f. the IdenticalEtag error).
			ifModifiedSince, err := http.ParseTime(fhttp.Header.Get("Last-Modified"))
			c.conditionalRequestLock.Lock()
			if err == nil {
				c.lastModified[file] = ifModifiedSince
			} else {
				delete(c.lastModified, file)
			}
			c.conditionalRequestLock.Unlock()
		}
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, -1, false, err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, -1, false, err
	}
	return data, -1, false, nil
}
