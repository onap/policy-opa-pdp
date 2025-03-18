// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025: Deutsche Telekom
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

package utils

import (
	"strings"
)

// Custom type for sorting
type ByDotCount struct {
	Keys   []string
	Ascend bool
}

// Implement sort.Interface for ByDotCount
func (a ByDotCount) Len() int { return len(a.Keys) }

func (a ByDotCount) Swap(i, j int) { a.Keys[i], a.Keys[j] = a.Keys[j], a.Keys[i] }

func (a ByDotCount) Less(i, j int) bool {
	if a.Ascend {
		return strings.Count(a.Keys[i], ".") < strings.Count(a.Keys[j], ".")
	}
	return strings.Count(a.Keys[i], ".") > strings.Count(a.Keys[j], ".")
}
