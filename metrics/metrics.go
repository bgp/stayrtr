package metrics

import (
	"log"
	"net/http"
	"strings"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
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
)

func initMetrics() {
	prometheus.MustRegister(NumberOfVRPs)
	prometheus.MustRegister(LastChange)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(RefreshStatusCode)
	prometheus.MustRegister(ClientsMetric)
	prometheus.MustRegister(PDUsRecv)
}

func MetricHTTP(metricsPath string, metricsAddr string) {
	http.Handle(metricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(metricsAddr, nil))
}

type MetricsEvent struct{}

func (m *MetricsEvent) ClientConnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Inc()
}

func (m *MetricsEvent) ClientDisconnected(c *rtr.Client) {
	ClientsMetric.WithLabelValues(c.GetLocalAddress().String()).Dec()
}

func (m *MetricsEvent) HandlePDU(c *rtr.Client, pdu rtr.PDU) {
	PDUsRecv.WithLabelValues(
		strings.ToLower(
			strings.Replace(
				rtr.TypeToString(
					pdu.GetType()),
				" ",
				"_", -1))).Inc()
}

func (m *MetricsEvent) UpdateMetrics(numIPv4 int, numIPv6 int, numIPv4filtered int, numIPv6filtered int, changed time.Time, refreshed time.Time, file string) {
	NumberOfVRPs.WithLabelValues("ipv4", "filtered", file).Set(float64(numIPv4filtered))
	NumberOfVRPs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(numIPv4))
	NumberOfVRPs.WithLabelValues("ipv6", "filtered", file).Set(float64(numIPv6filtered))
	NumberOfVRPs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(numIPv6))
	LastChange.WithLabelValues(file).Set(float64(changed.UnixNano() / 1e9))
}

func init() {
	initMetrics()
}
