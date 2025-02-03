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
var IndeterminantDecisionsCount int64
var TotalErrorCount int64
var DecisionSuccessCount int64
var DecisionFailureCount int64
var mu sync.Mutex

// Increment counter
func IncrementIndeterminantDecisionsCount() {
	mu.Lock()
	IndeterminantDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func IndeterminantDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &IndeterminantDecisionsCount
}




// Increment counter
func IncrementTotalErrorCount() {
	mu.Lock()
	TotalErrorCount++
	mu.Unlock()
}

// returns pointer to the counter
func TotalErrorCountRef() *int64 {
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
func TotalDecisionSuccessCountRef() *int64 {
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
