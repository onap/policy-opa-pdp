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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounters(t *testing.T) {
	var wg sync.WaitGroup

	// Test IncrementTotalErrorCount and TotalErrorCountRef
	TotalErrorCount = 0
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			IncrementTotalErrorCount()
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(5), *totalErrorCountRef())

	// Test IncrementQuerySuccessCount and TotalQuerySuccessCountRef

	DecisionSuccessCount = 0

	wg.Add(7)

	for i := 0; i < 7; i++ {

		go func() {

			defer wg.Done()

			IncrementDecisionSuccessCount()

		}()

	}

	wg.Wait()

	assert.Equal(t, int64(7), *totalDecisionSuccessCountRef())

	// Test IncrementDecisionFailureCount and TotalDecisionFailureCountRef

	DecisionFailureCount = 0

	wg.Add(3)

	for i := 0; i < 3; i++ {

		go func() {

			defer wg.Done()

			IncrementDecisionFailureCount()

		}()

	}

	wg.Wait()

	assert.Equal(t, int64(3), *TotalDecisionFailureCountRef())

}
