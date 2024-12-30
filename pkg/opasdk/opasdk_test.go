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

package opasdk

import (
	"errors"
	"io"
	"os"
	"policy-opa-pdp/consts"
	"testing"
	"sync"
        "context"
	"fmt"
	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/open-policy-agent/opa/sdk"
)

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

type MockSDK struct {
    mock.Mock
}

func (m *MockSDK) New(ctx context.Context, options sdk.Options) (*sdk.OPA, error) {
    fmt.Print("Inside New Method")
    args := m.Called(ctx, options)
    return args.Get(0).(*sdk.OPA), args.Error(1)
}

func TestGetOPASingletonInstance_ConfigurationFileNotexisting(t *testing.T) {
	consts.OpasdkConfigPath = "/app/config/config.json"
	opaInstance, err := GetOPASingletonInstance()
	fmt.Print(err)
	//assert.NotNil(t, err) //error no such file or directory /app/config/config.json
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

func TestGetOPASingletonInstance_ConfigurationFileLoaded(t *testing.T) {
        tmpFile, err := os.CreateTemp("", "config.json")
        if err != nil {
                t.Fatalf("Failed to create temp file: %v", err)
        }
        defer os.Remove(tmpFile.Name())

        consts.OpasdkConfigPath = tmpFile.Name()

        // Simulate OPA instance creation
        opaInstance, err := GetOPASingletonInstance()

        // Assertions
        assert.Nil(t, err)
        assert.NotNil(t, opaInstance)
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

func TestGetOPASingletonInstance_JSONReadError(t *testing.T) {
        consts.OpasdkConfigPath = "/app/config/config.json"

        // Simulate an error in JSON read (e.g., corrupt file)
        mockReadAll := func(r io.Reader) ([]byte, error) {
                return nil, errors.New("Failed to read JSON file")
        }

        jsonReader, err := getJSONReader(consts.OpasdkConfigPath, os.Open, mockReadAll)
        assert.NotNil(t, err)
        assert.Nil(t, jsonReader)
}

func TestGetOPASingletonInstance_ValidConfigFile(t *testing.T) {
        tmpFile, err := os.CreateTemp("", "config.json")
        if err != nil {
                t.Fatalf("Failed to create temp file: %v", err)
        }
        defer os.Remove(tmpFile.Name())

        consts.OpasdkConfigPath = tmpFile.Name()

        // Valid JSON content
        validJSON := []byte(`{"config": "test"}`)
        err = os.WriteFile(tmpFile.Name(), validJSON, 0644)
        if err != nil {
                t.Fatalf("Failed to write valid JSON to temp file: %v", err)
        }

        // Call the function
        opaInstance, err := GetOPASingletonInstance()

        assert.Nil(t, err)
        assert.NotNil(t, opaInstance)
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

func TestGetJSONReader_ReadAllError(t *testing.T) {
        mockFile := new(MockFile)
        mockFile.On("Open", "/app/config/config.json").Return(&os.File{}, nil)

        // Simulate ReadAll error
        jsonReader, err := getJSONReader("/app/config/config.json", mockFile.Open, func(r io.Reader) ([]byte, error) {
                return nil, io.ErrUnexpectedEOF
        })

        assert.Error(t, err)
        assert.Nil(t, jsonReader)

        mockFile.AssertCalled(t, "Open", "/app/config/config.json")
}


func TestGetOPASingletonInstance(t *testing.T) {
    // Call your function under test
    opaInstance, err := GetOPASingletonInstance()

    // Assertions
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
    if opaInstance == nil {
        t.Error("Expected OPA instance, got nil")
    }
    assert.NotNil(t, opaInstance, "OPA instance should be nil when sdk.New fails")
}


// Helper to reset the singleton for testing
func resetSingleton() {
	opaInstance = nil
	once = sync.Once{}
}

// Test sdk.New failure scenario
func TestGetOPASingletonInstance_SdkNewFails(t *testing.T) {
	resetSingleton()
	// Patch sdk.New to simulate a failure
	monkey.Patch(sdk.New, func(ctx context.Context, options sdk.Options) (*sdk.OPA, error) {
		return nil, errors.New("mocked error in sdk.New")
	})
	defer monkey.Unpatch(sdk.New)
	opaInstance, err := GetOPASingletonInstance()
	assert.Nil(t, opaInstance, "OPA instance should be nil when sdk.New fails")
	assert.Error(t, err, "Expected an error when sdk.New fails")
	assert.Contains(t, err.Error(), "mocked error in sdk.New")
}
