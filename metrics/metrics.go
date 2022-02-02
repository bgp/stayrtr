package metrics

import (
	"log"
	"net/http"

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

func init() {
	initMetrics()
}
