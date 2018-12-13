package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
)

var (
	newCertsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_manager_new_certificates_total",
		Help: "The total number of successfully generated new certs",
	})

	renewalCertsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_manager_renewed_certificates_total",
		Help: "The total number of successfully renewed certs",
	})

	failedCert = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_manager_failed_certificates_total",
		Help: "The total number of failed certs",
	})
)

func startPrometheus() {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":2112", nil))
	}()
}

func recordSuccessfulCert(isUpdate bool) {
	if isUpdate {
		renewalCertsProcessed.Inc()
	} else {
		newCertsProcessed.Inc()
	}
}

func recordFailedCert() {
	failedCert.Inc()
}
