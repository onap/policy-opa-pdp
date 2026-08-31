// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2026: Deutsche Telekom
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

package readiness

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsReady_DefaultsToNotReady(t *testing.T) {
	t.Cleanup(func() { SetReady(false) })

	assert.False(t, IsReady(), "an instance must not be routed to before startup completes")
}

func TestSetReady(t *testing.T) {
	t.Cleanup(func() { SetReady(false) })

	SetReady(true)
	assert.True(t, IsReady())

	SetReady(false)
	assert.False(t, IsReady())
}

// Startup and shutdown write the flag from main while probe requests read it from
// their own goroutines.
func TestReadiness_ConcurrentAccess(t *testing.T) {
	t.Cleanup(func() { SetReady(false) })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				SetReady(i%4 == 0)
				return
			}
			IsReady()
		}(i)
	}
	wg.Wait()
}
