// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2025: Deutsche Telekom
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
	"net/http"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/bundleserver"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/decision"
	"policy-opa-pdp/pkg/healthcheck"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/opasdk"
)

// RegisterHandlers registers the HTTP handlers for the service.
func RegisterHandlers() {

	// Handler for OPA decision making
	opaDecisionHandler := http.HandlerFunc(decision.OpaDecision)
	http.Handle("/policy/pdpo/v1/decision", basicAuth(opaDecisionHandler))

	//This api is used internally by OPA-SDK
	bundleServerHandler := http.HandlerFunc(bundleserver.GetBundle)
	http.Handle("/opa/bundles/", bundleServerHandler)

	// Handler for kubernetes readiness probe
	readinessProbeHandler := http.HandlerFunc(readinessProbe)
	http.Handle("/ready", readinessProbeHandler)

	// Handler for health checks
	healthCheckHandler := http.HandlerFunc(healthcheck.HealthCheckHandler)
	http.HandleFunc("/policy/pdpo/v1/healthcheck", basicAuth(healthCheckHandler))

	// Handler for statistics report
	statisticsReportHandler := http.HandlerFunc(metrics.FetchCurrentStatistics)
	http.HandleFunc("/policy/pdpo/v1/statistics", basicAuth(statisticsReportHandler))

	listPoliciesHandler := http.HandlerFunc(opasdk.ListPolicies)
	http.Handle("/opa/listpolicies", listPoliciesHandler)

	dataHandler := http.HandlerFunc(data.DataHandler)
	http.Handle("/policy/pdpo/v1/data/", basicAuth(dataHandler))

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

// validates Credentials for http server
func validateCredentials(username, password string) bool {
	validUser := cfg.Username
	validPass := cfg.Password
	return username == validUser && password == validPass
}

// handles readiness probe endpoint
func readinessProbe(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	_, err := res.Write([]byte("Ready"))
	if err != nil {
		log.Errorf("Failed to write response: %v", err)
	}
}
