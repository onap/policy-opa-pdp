// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2026: Deutsche Telekom
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//   SPDX-License-Identifier: Apache-2.0
//   ========================LICENSE_END===================================

// Package api provides HTTP handlers for the policy-opa-pdp service.
// This package includes handlers for decision making, bundle serving, health checks, and readiness probes.
// It also includes basic authentication middleware for securing certain endpoints.
package api

import (
	"crypto/subtle"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/astgenerator"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/decision"
	"policy-opa-pdp/pkg/healthcheck"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/opasdk"
	"time"
)

// requestIdAttribute carries the ONAP correlation id on the server span, so a
// trace can be found from an X-ONAP-RequestID and vice versa.
const requestIdAttribute = "onap.request.id"

// RegisterHandlers registers the HTTP handlers for the service.
//
// Tracing note: /metrics, /healthcheck and /readiness are deliberately left
// uninstrumented. Prometheus scrapes and kubelet probes are high-frequency and
// carry no correlation value, so tracing them would bury the request traces that
// matter.
func RegisterHandlers() {

	// Handler for OPA decision making
	opaDecisionHandler := http.HandlerFunc(decision.OpaDecision)
	http.Handle("/policy/pdpo/v1/decision",
		instrument(basicAuth(trackDecisionResponseTime(opaDecisionHandler))))

	// Handler for health checks
	healthCheckHandler := http.HandlerFunc(healthcheck.HealthCheckHandler)
	http.HandleFunc("/policy/pdpo/v1/healthcheck", basicAuth(healthCheckHandler))

	// Handler for AST Generator
	astGeneratorHandler := http.HandlerFunc(astgenerator.ASTGeneratorHandler)
	http.Handle("/policy/pdpo/v1/generateast",
		instrument(basicAuth(astGeneratorHandler)))

	// Handler for statistics report
	statisticsReportHandler := http.HandlerFunc(metrics.FetchCurrentStatistics)
	http.Handle("/policy/pdpo/v1/statistics",
		instrument(basicAuth(statisticsReportHandler)))

	listPoliciesHandler := http.HandlerFunc(opasdk.ListPolicies)
	http.Handle("/opa/listpolicies",
		instrument(basicAuth(listPoliciesHandler)))

	dataHandler := http.HandlerFunc(data.DataHandler)
	http.Handle("/policy/pdpo/v1/data/",
		instrument(basicAuth(trackDataResponseTime(dataHandler))))

	http.Handle("/policy/pdpo/v1/data",
		instrument(basicAuth(trackDataResponseTime(dataHandler))))

	http.Handle("/metrics", basicAuth(http.HandlerFunc(metricsHandler)))

	// Readiness probe — intentionally unauthenticated for K8s probe compatibility
	http.HandleFunc("/policy/pdpo/v1/readiness", readinessProbe)

}

// instrument wraps next in an OpenTelemetry server span.
//
// The span is the outermost wrapper, outside basicAuth, so that requests rejected
// for bad credentials still produce a span — an authentication failure is exactly
// the kind of event a trace should show.
//
// otelhttp names the span "{method} {pattern}" from the ServeMux pattern, per the
// HTTP semantic conventions. The method matters here: /data serves both GET and
// PATCH, and naming by route alone would merge the two.
func instrument(next http.Handler) http.Handler {
	return otelhttp.NewHandler(withRequestIdAttribute(next), "")
}

func withRequestIdAttribute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if requestId := req.Header.Get(consts.RequestId); requestId != "" {
			trace.SpanFromContext(req.Context()).SetAttributes(
				attribute.String(requestIdAttribute, requestId))
		}
		next.ServeHTTP(res, req)
	})
}

// Define the metrics handler function
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

// Track Decision response time metrics
func trackDecisionResponseTime(next http.HandlerFunc) http.HandlerFunc {
	return trackResponseTime(metrics.DecisionResponseTime_Prom, next)
}

// Track Data response time metrics
func trackDataResponseTime(next http.HandlerFunc) http.HandlerFunc {
	return trackResponseTime(metrics.DataResponseTime_Prom, next)
}

func trackResponseTime(metricCollector prometheus.Observer, next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		start := time.Now()
		next(res, req)
		duration := time.Since(start).Seconds()
		metricCollector.Observe(duration)
	}
}

// handles authentication
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		user, pass, ok := req.BasicAuth()
		if !ok || !validateCredentials(user, pass) {
			res.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(res, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(res, req)
	}
}

// validates Credentials for http server using constant-time comparison
// to prevent timing-based credential enumeration attacks.
// Fail closed: empty configured or supplied credentials are rejected before the
// constant-time compare so that an unset API_PASSWORD (empty string) does not
// allow an empty-password request through (subtle.ConstantTimeCompare("","") == 1).
func validateCredentials(username, password string) bool {
	if cfg.Username == "" || cfg.Password == "" || username == "" || password == "" {
		return false
	}
	u := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Username))
	p := subtle.ConstantTimeCompare([]byte(password), []byte(cfg.Password))
	return u == 1 && p == 1
}

// handles readiness probe endpoint
func readinessProbe(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	_, err := res.Write([]byte("Ready"))
	if err != nil {
		log.Errorf("Failed to write response: %v", err)
	}
}
