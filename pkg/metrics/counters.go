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

import "sync"

// global counter variables
var TotalErrorCount int64
var DecisionSuccessCount int64
var DecisionFailureCount int64
var DeployFailureCount int64
var DeploySuccessCount int64
var UndeployFailureCount int64
var UndeploySuccessCount int64
var TotalPoliciesCount int64
var mu sync.Mutex

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

// Increment counter
func IncrementDecisionSuccessCount() {
	mu.Lock()
	DecisionSuccessCount++
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
