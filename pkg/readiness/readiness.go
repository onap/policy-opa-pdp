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

// The readiness package records whether startup has finished, so the readiness probe
// can tell an orchestrator whether this instance may be routed to. It is deliberately
// separate from the healthcheck, which reports liveness: a live process that has not
// finished starting up must not be sent traffic, but it must not be restarted either.
package readiness

import "sync"

var (
	mu    sync.RWMutex
	ready bool
)

// SetReady records whether startup has completed. Startup calls it once everything a
// decision needs is in place.
func SetReady(state bool) {
	mu.Lock()
	defer mu.Unlock()
	ready = state
}

// IsReady reports whether startup has completed.
func IsReady() bool {
	mu.RLock()
	defer mu.RUnlock()
	return ready
}
