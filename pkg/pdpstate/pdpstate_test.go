// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telecom
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
//   ========================LICENSE_END===================================
//

package pdpstate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"policy-opa-pdp/pkg/model"
)

func TestSetState_Success(t *testing.T) {
	t.Run("ValidState", func(t *testing.T) {
		err := SetState("ACTIVE")
		assert.NoError(t, err, "Expected no error for valid state")
		assert.Equal(t, model.Active, GetState(), "Expected state to be set to Active")
	})
}

func TestSetState_Failure(t *testing.T) {
	State = model.Passive
	t.Run("InvalidState", func(t *testing.T) {
		err := SetState("InvalidState")
		assert.Error(t, err, "Expected an error for invalid state")
		assert.Equal(t, model.Passive, GetState(), "Expected state to remain unchanged when setting invalid state")
	})
}
