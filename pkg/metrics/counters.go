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
//

package metrics

import (
        "sync"
        "github.com/prometheus/client_golang/prometheus"
)
// global counter variables
var TotalErrorCount int64
var DecisionSuccessCount int64
var DecisionFailureCount int64
var DeployFailureCount int64
var DeploySuccessCount int64
var UndeployFailureCount int64
var UndeploySuccessCount int64
var TotalPoliciesCount int64
var DynamicDataUpdateSuccessCount int64
var DynamicDataUpdateFailureCount int64
var mu sync.Mutex

//Decision and Data counters to be used in prometheus
var (
	DecisionResponseTime_Prom = prometheus.NewSummary(prometheus.SummaryOpts{
		Name:    "opa_decision_response_time_seconds",
		Help:    "Response time of OPA decision handler",
	})
	DataResponseTime_Prom = prometheus.NewSummary(prometheus.SummaryOpts{
		Name:    "opa_data_response_time_seconds",
		Help:    "Response time of OPA data handler",
	})
	DecisionHandlerCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_policy_decisions_total",
                Help:    "Total Number of Decision Handler hits for OPA",
        })
        DeploymentSuccessCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_policy_deployments_total",
                Help:    "Total Number of Successful Deployment for OPA",
        })
        DeploymentFailureCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_policy_failures_total",
                Help:    "Total Number of Deployment Failures for OPA",
        })
        DynamicDataUpdatesSuccessCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_dynamic_data_success_total",
                Help:    "Total Number of Successful Dynamic Data Updates for OPA",
        })
        DynamicDataUpdatesFailureCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_dynamic_data_failures_total",
                Help:    "Total Number of Failed Dynamic Data Updates for OPA",
        })
        UndeploymentSuccessCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_policy_undeployments_success_total",
                Help:    "Total Number of Successful Deployment for OPA",
        })
        UndeploymentFailureCount_Prom = prometheus.NewCounter(prometheus.CounterOpts{
                Name:    "pdpo_policy_undeployments_failures_total",
                Help:    "Total Number of Deployment Failures for OPA",
        })
)

//register counters in init
func init() {
	prometheus.MustRegister(DecisionResponseTime_Prom)
	prometheus.MustRegister(DataResponseTime_Prom)
	prometheus.MustRegister(DecisionHandlerCount_Prom)
        prometheus.MustRegister(DeploymentSuccessCount_Prom)
        prometheus.MustRegister(DeploymentFailureCount_Prom)
        prometheus.MustRegister(DynamicDataUpdatesSuccessCount_Prom)
        prometheus.MustRegister(DynamicDataUpdatesFailureCount_Prom)
        prometheus.MustRegister(UndeploymentSuccessCount_Prom)
        prometheus.MustRegister(UndeploymentFailureCount_Prom)
}

// Increment counter
func IncrementTotalErrorCount() {
	mu.Lock()
	TotalErrorCount++
	mu.Unlock()
}

// returns pointer to the counter
func totalErrorCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &TotalErrorCount
}

func IncrementDynamicDataUpdateSuccessCount() {
	mu.Lock()
	DynamicDataUpdateSuccessCount++
	DynamicDataUpdatesSuccessCount_Prom.Inc()
	mu.Unlock()
}

func totalDynamicDataUpdateSuccessCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DynamicDataUpdateSuccessCount

}

func IncrementDynamicDataUpdateFailureCount() {
	mu.Lock()
	DynamicDataUpdateFailureCount++
	DynamicDataUpdatesFailureCount_Prom.Inc()
	mu.Unlock()
}

func totalDynamicDataUpdateFailureCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DynamicDataUpdateFailureCount

}

// Increment counter
func IncrementDecisionSuccessCount() {
	mu.Lock()
	DecisionSuccessCount++
	DecisionHandlerCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter
func totalDecisionSuccessCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DecisionSuccessCount

}

// Increment counter
func IncrementDecisionFailureCount() {
	mu.Lock()
	DecisionFailureCount++
	DecisionHandlerCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter
func TotalDecisionFailureCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DecisionFailureCount

}

// Increment counter
func IncrementDeploySuccessCount() {
	mu.Lock()
	DeploySuccessCount++
	DeploymentSuccessCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter

func totalDeploySuccessCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DeploySuccessCount

}

// Increment counter
func IncrementDeployFailureCount() {
	mu.Lock()
	DeployFailureCount++
	DeploymentFailureCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter

func totalDeployFailureCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DeployFailureCount

}

// Increment counter
func IncrementUndeploySuccessCount() {
	mu.Lock()
	UndeploySuccessCount++
	UndeploymentSuccessCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter

func totalUndeploySuccessCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &UndeploySuccessCount

}

// Increment counter
func IncrementUndeployFailureCount() {
	mu.Lock()
	UndeployFailureCount++
	UndeploymentFailureCount_Prom.Inc()
	mu.Unlock()
}

// returns pointer to the counter

func totalUndeployFailureCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &UndeployFailureCount

}

// Increment counter
func SetTotalPoliciesCount(newCount int64) {
	mu.Lock()
	TotalPoliciesCount = newCount
	mu.Unlock()
}

// returns pointer to the counter

func totalPoliciesCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &TotalPoliciesCount
}
