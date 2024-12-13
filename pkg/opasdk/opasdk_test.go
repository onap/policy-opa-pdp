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

package opasdk

import (
	"io"
	"os"
	"policy-opa-pdp/consts"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetOPASingletonInstance_ConfigurationFileNotexisting(t *testing.T) {
	consts.OpasdkConfigPath = "/app/config/config.json"
	opaInstance, err := GetOPASingletonInstance()
	assert.NotNil(t, err) //error no such file or directory /app/config/config.json
	assert.NotNil(t, opaInstance)
}

func TestGetOPASingletonInstance_SingletonBehavior(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	consts.OpasdkConfigPath = tmpFile.Name()

	// Call the function multiple times
	opaInstance1, err1 := GetOPASingletonInstance()
	opaInstance2, err2 := GetOPASingletonInstance()

	// Assertions
	assert.Nil(t, err1)
	assert.Nil(t, err2)
	assert.NotNil(t, opaInstance1)
	assert.NotNil(t, opaInstance2)
	assert.Equal(t, opaInstance1, opaInstance2) // Ensure it's the same instance
}

func TestGetOPASingletonInstance_OPAInstanceCreation(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	consts.OpasdkConfigPath = tmpFile.Name()

	// Call the function
	opaInstance, err := GetOPASingletonInstance()

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, opaInstance)
}

// Mock for os.Open
type MockFile struct {
	mock.Mock
}

func (m *MockFile) Open(name string) (*os.File, error) {
	args := m.Called(name)
	return args.Get(0).(*os.File), args.Error(1)
}

// Mock for io.ReadAll
func mockReadAll(r io.Reader) ([]byte, error) {
	return []byte(`{"config": "test"}`), nil
}

func TestGetJSONReader(t *testing.T) {
	// Create a mock file
	mockFile := new(MockFile)
	mockFile.On("Open", "/app/config/config.json").Return(&os.File{}, nil)

	// Call the function with mock functions
	jsonReader, err := getJSONReader("/app/config/config.json", mockFile.Open, mockReadAll)

	// Check the results
	assert.NoError(t, err)
	assert.NotNil(t, jsonReader)

	// Check the content of the jsonReader
	expectedContent := `{"config": "test"}`
	actualContent := make([]byte, len(expectedContent))
	jsonReader.Read(actualContent)
	assert.Equal(t, expectedContent, string(actualContent))

	// Assert that the mock methods were called
	mockFile.AssertCalled(t, "Open", "/app/config/config.json")
}
