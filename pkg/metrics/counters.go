// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telekom
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
var PermitDecisionsCount int64
var DenyDecisionsCount int64
var TotalErrorCount int64
var QuerySuccessCount int64
var QueryFailureCount int64
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
func IncrementPermitDecisionsCount() {
	mu.Lock()
	PermitDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func PermitDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &PermitDecisionsCount
}

// Increment counter
func IncrementDenyDecisionsCount() {
	mu.Lock()
	DenyDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func DenyDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DenyDecisionsCount
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
func IncrementQuerySuccessCount() {
	mu.Lock()
	QuerySuccessCount++
	mu.Unlock()
}

// returns pointer to the counter
func TotalQuerySuccessCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &QuerySuccessCount

}

// Increment counter
func IncrementQueryFailureCount() {
	mu.Lock()
	QueryFailureCount++
	mu.Unlock()
}

// returns pointer to the counter
func TotalQueryFailureCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &QueryFailureCount

}
