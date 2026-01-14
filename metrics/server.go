package metrics

import "github.com/prometheus/client_golang/prometheus"

type ServerMetrics struct {
	NumberOfVRPs      *prometheus.GaugeVec
	NumberOfObjects   *prometheus.GaugeVec
	LastRefresh       *prometheus.GaugeVec
	LastChange        *prometheus.GaugeVec
	RefreshStatusCode *prometheus.CounterVec
	ClientsMetric     *prometheus.GaugeVec
	PDUsRecv          *prometheus.CounterVec
	CurrentSerial     prometheus.Gauge
}

func NewServerMetrics() *ServerMetrics {
	metrics := &ServerMetrics{}
	metrics.NumberOfVRPs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_vrps",
			Help: "Number of VRPs by source and status.",
		},
		[]string{"ip_version", "filtered", "path"},
	)
	metrics.NumberOfObjects = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_objects",
			Help: "Number of RPKI objects (in cache) by type",
		},
		[]string{"type"},
	)
	metrics.LastRefresh = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_refresh",
			Help: "Last successful request for the given URL.",
		},
		[]string{"path"},
	)
	metrics.LastChange = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_change",
			Help: "Last change.",
		},
		[]string{"path"},
	)
	metrics.RefreshStatusCode = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "refresh_requests_total",
			Help: "Total number of HTTP requests by status code",
		},
		[]string{"path", "code"},
	)
	metrics.ClientsMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtr_clients",
			Help: "Number of clients connected.",
		},
		[]string{"bind"},
	)
	metrics.PDUsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rtr_pdus",
			Help: "PDU received.",
		},
		[]string{"type"},
	)
	metrics.CurrentSerial = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rtr_serial",
			Help: "Current serial.",
		},
	)
	metrics.initMetrics()
	return metrics
}

func (m *ServerMetrics) initMetrics() {
	prometheus.MustRegister(m.NumberOfObjects)
	prometheus.MustRegister(m.NumberOfVRPs)
	prometheus.MustRegister(m.LastChange)
	prometheus.MustRegister(m.LastRefresh)
	prometheus.MustRegister(m.RefreshStatusCode)
	prometheus.MustRegister(m.ClientsMetric)
	prometheus.MustRegister(m.PDUsRecv)
	prometheus.MustRegister(m.CurrentSerial)
}
