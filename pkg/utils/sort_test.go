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

// Package provides sorting functionalities. 

package utils

import (
	"sort"
	"testing"
)

// Test sorting in ascending order by dot count
func TestByDotCountAscending(t *testing.T) {
	keys := []string{"a.b.c", "a.b", "a.b.c.d", "a"}
	expected := []string{"a", "a.b", "a.b.c", "a.b.c.d"}

	sort.Sort(ByDotCount{Keys: keys, Ascend: true})

	for i, v := range keys {
		if v != expected[i] {
			t.Errorf("Ascending sort failed. Expected %s, got %s", expected[i], v)
		}
	}
}

// Test sorting in descending order by dot count
func TestByDotCountDescending(t *testing.T) {
	keys := []string{"a.b.c", "a.b", "a.b.c.d", "a"}
	expected := []string{"a.b.c.d", "a.b.c", "a.b", "a"}

	sort.Sort(ByDotCount{Keys: keys, Ascend: false})

	for i, v := range keys {
		if v != expected[i] {
			t.Errorf("Descending sort failed. Expected %s, got %s", expected[i], v)
		}
	}
}

// Test sorting with equal dot counts
func TestByDotCountEqualDots(t *testing.T) {
	keys := []string{"a.b.c", "x.y.z", "m.n.o"}
	expected := []string{"a.b.c", "x.y.z", "m.n.o"} // Order should be preserved as all have same dots

	sort.Sort(ByDotCount{Keys: keys, Ascend: true})

	for i, v := range keys {
		if v != expected[i] {
			t.Errorf("Equal dot count sorting failed. Expected %s, got %s", expected[i], v)
		}
	}
}
