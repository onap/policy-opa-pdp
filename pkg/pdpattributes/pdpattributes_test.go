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

package pdpattributes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateUniquePdpName_Success(t *testing.T) {
	t.Run("GenerateValidPdpName", func(t *testing.T) {
		pdpName := GenerateUniquePdpName()
		assert.Contains(t, pdpName, "opa-", "Expected PDP name to start with 'opa-'")
	})
}

func TestGenerateUniquePdpName_Failure(t *testing.T) {
	t.Run("UniqueNamesCheck", func(t *testing.T) {
		pdpName1 := GenerateUniquePdpName()
		pdpName2 := GenerateUniquePdpName()
		assert.NotEqual(t, pdpName1, pdpName2, "Expected different UUID for each generated PDP name")
		assert.Len(t, pdpName1, len("opa-")+36, "Expected length of PDP name to match 'opa-<UUID>' format")
	})
}

func TestSetPdpSubgroup_Success(t *testing.T) {
	t.Run("ValidSubgroup", func(t *testing.T) {
		expectedSubgroup := "subgroup1"
		SetPdpSubgroup(expectedSubgroup)
		assert.Equal(t, expectedSubgroup, GetPdpSubgroup(), "Expected PDP subgroup to match set value")
	})
}

func TestSetPdpSubgroup_Failure(t *testing.T) {
	t.Run("EmptySubgroup", func(t *testing.T) {
		SetPdpSubgroup("")
		assert.Equal(t, "", GetPdpSubgroup(), "Expected PDP subgroup to be empty when set to empty string")
	})

	t.Run("LargeSubgroup", func(t *testing.T) {
		largeSubgroup := make([]byte, 1024*1024) // 1MB of 'a' characters
		for i := range largeSubgroup {
			largeSubgroup[i] = 'a'
		}
		SetPdpSubgroup(string(largeSubgroup))
		assert.Equal(t, string(largeSubgroup), GetPdpSubgroup(), "Expected large PDP subgroup to match set value")
	})
}

func TestSetPdpHeartbeatInterval_Success(t *testing.T) {
	t.Run("ValidHeartbeatInterval", func(t *testing.T) {
		expectedInterval := int64(30)
		SetPdpHeartbeatInterval(expectedInterval)
		assert.Equal(t, expectedInterval, GetPdpHeartbeatInterval(), "Expected heartbeat interval to match set value")
	})
}

func TestSetPdpHeartbeatInterval_Failure(t *testing.T) {
	t.Run("FailureHeartbeatInterval", func(t *testing.T) {
		SetPdpHeartbeatInterval(-10)
		assert.Equal(t, int64(-10), GetPdpHeartbeatInterval(), "Expected heartbeat interval to handle negative values")
	})

	t.Run("LargeHeartbeatInterval", func(t *testing.T) {
		largeInterval := int64(time.Hour * 24 * 365 * 10) // 10 years in seconds
		SetPdpHeartbeatInterval(largeInterval)
		assert.Equal(t, largeInterval, GetPdpHeartbeatInterval(), "Expected PDP heartbeat interval to handle large values")
	})
}
