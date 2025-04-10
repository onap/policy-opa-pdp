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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"policy-opa-pdp/consts"
	"sync"
	"testing"
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

type MockStorage struct {
	mock.Mock
}

type MockTransaction struct{}

func (m *MockTransaction) ID() uint64 {
	return 1
}

func (m *MockStorage) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	args := m.Called(ctx, params)
	return &MockTransaction{}, args.Error(1)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Read(ctx context.Context, txn storage.Transaction, path storage.Path) (interface{}, error) {
	args := m.Called(ctx, txn, path)
	return args.Get(0), args.Error(1)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Write(ctx context.Context, txn storage.Transaction, op storage.PatchOp, path storage.Path, value interface{}) error {
	args := m.Called(ctx, txn, op, path, value)
	return args.Error(0)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Commit(ctx context.Context, txn storage.Transaction) error {
	args := m.Called(ctx, txn)
	return args.Error(0)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Abort(ctx context.Context, txn storage.Transaction) {
	m.Called(ctx, txn)
}

// Implement the Register method.
func (m *MockStorage) Register(ctx context.Context, txn storage.Transaction, config storage.TriggerConfig) (storage.TriggerHandle, error) {
	// Return mock values (adjust as needed for tests)
	return nil, nil
}

func (m *MockStorage) Truncate(ctx context.Context, txn storage.Transaction, params storage.TransactionParams, iter storage.Iterator) error {
	return nil // Adjust return as needed for your test
}

func (m *MockStorage) DeletePolicy(ctx context.Context, txn storage.Transaction, id string) error {
	args := m.Called(ctx, txn, id)
	return args.Error(0)
}

func (m *MockStorage) UpsertPolicy(ctx context.Context, txn storage.Transaction, policyID string, policyContent []byte) error {
	args := m.Called(ctx, txn, policyID, policyContent)
	return args.Error(0)
}

func (m *MockStorage) GetPolicy(ctx context.Context, txn storage.Transaction, id string) ([]byte, error) {
	args := m.Called(ctx, txn, id)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockStorage) ListPolicies(ctx context.Context, txn storage.Transaction) ([]string, error) {
	args := m.Called(ctx, txn)
	return args.Get(0).([]string), args.Error(1)
}

type MockData struct {
	Value string `json:"value"`
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
	NewSDK = func(ctx context.Context, options sdk.Options) (*sdk.OPA, error) {
		return nil, errors.New("mocked error in sdk.New")
	}
	opaInstance, err := GetOPASingletonInstance()
	assert.Nil(t, opaInstance, "OPA instance should be nil when sdk.New fails")
	assert.Error(t, err, "Expected an error when sdk.New fails")
	assert.Contains(t, err.Error(), "mocked error in sdk.New")
}

func TestInitializePath_ReadSuccess(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(MockTransaction)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil, nil)

	err := initializePath(ctx, txn, "/some/path")

	assert.Nil(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestInitializePath_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(MockTransaction)

	// Define the mock data in the same format as Read() would return
	mockData := map[string]interface{}{"value": "testValue"}

	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mockData, errors.New("data write error"))

	err := initializePath(ctx, txn, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "data write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	var content interface{} = "test-content"
	err := WriteData(ctx, "/some/path", content)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_ReadError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil, errors.New("read error in initializePath method"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	var content interface{} = "test-content"
	err := WriteData(ctx, "/some/path", content)

	assert.Error(t, err)
	assert.Equal(t, "read error in initializePath method", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("data write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	var data interface{} = "test-content"
	err := WriteData(ctx, "/some/path", data)

	assert.Error(t, err)
	assert.Equal(t, "data write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data := []byte("test-content")
	err := WriteData(ctx, "/some/path", data)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data := []byte("test-content")
	err := WriteData(ctx, "/some/path", data)

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(errors.New("upsert policy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "upsert policy error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{}, errors.New("ListPolicies error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_GetPolicyError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{"policyId"}, nil)
	mockMemStore.On("GetPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), "policyId").Return([]byte{}, errors.New("GetPolicy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_GetPolicySuccess(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{"policyId"}, nil)
	mockMemStore.On("GetPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), "policyId").Return([]byte{}, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	//	assert.Nil(t, err)
	//	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{}, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	//	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(errors.New("DeletePolicy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "DeletePolicy error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore

	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestGetDataInfo_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	// Define the mock data in the same format as Read() would return
	mockData := map[string]interface{}{"value": "testValue"}
	mockDataJSON, _ := json.Marshal(mockData)

	// Ensure mock expectations match actual function calls
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(mockData, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, data)

	dataJson, errInfo := json.Marshal(data)
	assert.NoError(t, errInfo)

	assert.JSONEq(t, string(mockDataJSON), string(dataJson))
	mockMemStore.AssertExpectations(t)

}

func TestGetDataInfo_ReadError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(nil, errors.New("read error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, "read error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestGetDataInfo_JSONUnmarshalError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)
	invalidData := make(chan int) // Invalid type for JSON marshalling

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(invalidData, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	assert.Error(t, err)
	assert.Nil(t, data)
	mockMemStore.AssertExpectations(t)
}

func TestParsePatchPathEscaped_Success(t *testing.T) {
	cases := []struct {
		input    string
		expected storage.Path
	}{
		{"/valid/path", storage.Path{"valid", "path"}},
		{"/escaped~1path", storage.Path{"escaped/path"}},
		{"/double~1escaped~0tilde", storage.Path{"double/escaped~tilde"}},
	}

	for _, tc := range cases {
		path, ok := ParsePatchPathEscaped(tc.input)
		assert.True(t, ok)
		assert.Equal(t, tc.expected, path)
	}
}

func TestParsePatchPathEscaped_Failure(t *testing.T) {
	cases := []string{
		"",         // Empty string
		"~invalid", // Invalid leading tilde
	}

	for _, input := range cases {
		path, ok := ParsePatchPathEscaped(input)
		assert.False(t, ok)
		assert.Nil(t, path)
	}
}
