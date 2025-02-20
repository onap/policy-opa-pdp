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

// The opasdk package provides functionalities for integrating with the Open Policy Agent
// (OPA) SDK, including reading configurations and managing a singleton OPA instance.
// This package is designed to ensure efficient, thread-safe initialization and configuration
// of the OPA instance.
package opasdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/sdk"
	"github.com/open-policy-agent/opa/v1/storage"
	"policy-opa-pdp/pkg/model/oapicodegen"
)

// Define the structs
var (
	opaInstance *sdk.OPA  //A singleton instance of the OPA object
	once        sync.Once //A sync.Once variable used to ensure that the OPA instance is initialized only once,
	memStore    storage.Store
	UpsertPolicyVar UpsertPolicyFunc = UpsertPolicy
        WriteDataVar    WriteDataFunc    = WriteData
)

type (
        UpsertPolicyFunc func(ctx context.Context, policyID string, policyContent []byte) error
        WriteDataFunc    func(ctx context.Context, dataPath string, data interface{}) error
)

type PatchImpl struct {
	Path  storage.Path
	Op    storage.PatchOp
	Value interface{}
}

// reads JSON configuration from a file and return a jsonReader
func getJSONReader(filePath string, openFunc func(string) (*os.File, error),
	readAllFunc func(io.Reader) ([]byte, error)) (*bytes.Reader, error) {
	file, err := openFunc(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	byteValue, err := readAllFunc(file)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	jsonReader := bytes.NewReader(byteValue)
	return jsonReader, nil
}

type NewSDKFunc func(ctx context.Context, options sdk.Options) (*sdk.OPA, error)
var NewSDK NewSDKFunc = sdk.New

// Returns a singleton instance of the OPA object. The initialization of the instance is
// thread-safe, and the OPA object is configured using a JSON configuration file.
func GetOPASingletonInstance() (*sdk.OPA, error) {
	var err error
	memStore = inmem.New()
	once.Do(func() {
	        var opaErr error
	        opaInstance, opaErr = NewSDK(context.Background(), sdk.Options{
			// Configure your OPA instance here
			V1Compatible: true,
			Store:        memStore,
		})
		log.Debugf("Create an instance of OPA Object")
		if opaErr != nil {
			log.Warnf("Error creating OPA instance: %s", opaErr)
			err = opaErr
			return
		} else {
			jsonReader, jsonErr := getJSONReader(consts.OpasdkConfigPath, os.Open, io.ReadAll)
			if jsonErr != nil {
				log.Warnf("Error getting JSON reader: %s", jsonErr)
				err = jsonErr
				return
			}
			log.Debugf("Configure an instance of OPA Object")

			err := opaInstance.Configure(context.Background(), sdk.ConfigOptions{
				Config: jsonReader,
			})
			if err != nil {
			    log.Warnf("Failed to configure OPA: %v", err)
			}
		}
	})
	return opaInstance, err
}

func UpsertPolicy(ctx context.Context, policyID string, policyContent []byte) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.UpsertPolicy(ctx, txn, policyID, policyContent)
	if err != nil {
		log.Warnf("Error inserting policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func DeletePolicy(ctx context.Context, policyID string) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.DeletePolicy(ctx, txn, policyID)
	if err != nil {
		log.Warnf("Error deleting policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func WriteData(ctx context.Context, dataPath string, data interface{}) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	// Initialize the path if it doesn't exist
	err = initializePath(ctx, txn, dataPath)
	if err != nil {
		log.Warnf("Error initializling Path : %s", dataPath)
		log.Warnf("Error : %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	err = memStore.Write(ctx, txn, storage.AddOp, storage.MustParsePath(dataPath), data)
	if err != nil {
		log.Warnf("Error Adding data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil

}

func DeleteData(ctx context.Context, dataPath string) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Write(ctx, txn, storage.RemoveOp, storage.MustParsePath(dataPath), nil)
	if err != nil {
		log.Warnf("Error deleting data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

// Added below method to test get policies (added for testing purpose only)
func ListPolicies(res http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	rtxn, err := memStore.NewTransaction(ctx, storage.TransactionParams{Write: false})
	if err != nil {
		log.Warnf("Error creating transaction %s", err)
		memStore.Abort(ctx, rtxn)
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	policies, err := memStore.ListPolicies(ctx, rtxn)
	if err != nil {
		log.Warnf("Error ListPolicies %s", err)
		memStore.Abort(ctx, rtxn)
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, policyId := range policies {
		log.Debugf("Policy ID: %s", policyId)
		policy, err := memStore.GetPolicy(ctx, rtxn, policyId)
		if err != nil {
			log.Warnf("Error GetPolicy %s", err)
			memStore.Abort(ctx, rtxn)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Debugf("Policy Content: %s\n", string(policy))
	}
	memStore.Abort(ctx, rtxn)
	res.WriteHeader(http.StatusOK)
	if _, err := res.Write([]byte("Check logs")); err != nil {
		log.Warnf("Warning: Failed to write response: %v", err)
	}
}

func initializePath(ctx context.Context, txn storage.Transaction, path string) error {
	segments := storage.MustParsePath(path)
	for i := 1; i <= len(segments); i++ {
		subPath := segments[:i]
		_, err := memStore.Read(ctx, txn, subPath)
		if err != nil && storage.IsNotFound(err) {
			// Create the intermediate path
			log.Debugf("storage not found creating : %s", subPath.String())
			err = memStore.Write(ctx, txn, storage.AddOp, subPath, map[string]interface{}{})
			if err != nil {
				log.Debugf("Error initializing path: %s", err)
				return err
			}
		} else if err != nil {
			log.Debugf("Error reading path: %s", err)
			return err
		}
	}
	return nil
}

func PatchData(ctx context.Context, patches []PatchImpl) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error in creating transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	for _, patch := range patches {
		err = memStore.Write(ctx, txn, patch.Op, patch.Path, patch.Value)
		path := (patch.Path).String()
		if err != nil {
			log.Warnf("Error in writing data under "+path+" in memory: %s", err)
			memStore.Abort(ctx, txn)
			return err
		}
	}

	// Create a new compiler instance
	compiler := ast.NewCompiler()

	// Check for path conflicts
	errInfo := ast.CheckPathConflicts(compiler, storage.NonEmpty(ctx, memStore, txn))
	if len(errInfo) > 0 {
		memStore.Abort(ctx, txn)
		log.Errorf("Path conflicts detected: %s", errInfo)
		return errInfo
	} else {
		log.Debugf("No path conflicts detected")
	}

	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error in commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func GetDataInfo(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error) {

	rtxn, _ := memStore.NewTransaction(ctx, storage.TransactionParams{Write: false})
	defer memStore.Abort(ctx, rtxn) // Ensure transaction is aborted to avoid leaks
	path := storage.MustParsePath(dataPath)

	result, err := memStore.Read(ctx, rtxn, path)
	if err != nil {
		log.Warnf("Error in reading data under " + dataPath + " path")
		return nil, err
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Warnf("Error in converting result into json data %s", err)
		return nil, err
	}

	log.Debugf("Json Data at %s: %s\n", path, jsonData)

	var resData oapicodegen.OPADataResponse_Data

	err = json.Unmarshal(jsonData, &resData)
	if err != nil {
		log.Errorf("Error in unmarshalling data: %s", err)
		return nil, err
	}

	return &resData, nil
}

func ParsePatchPathEscaped(str string) (path storage.Path, ok bool) {
	path, ok = storage.ParsePathEscaped(str)
	if !ok {
		return
	}
	for i := range path {
		// RFC 6902 section 4: "[The "path" member's] value is a string containing
		// a JSON-Pointer value [RFC6901] that references a location within the
		// target document (the "target location") where the operation is performed."
		//
		// RFC 6901 section 3: "Because the characters '~' (%x7E) and '/' (%x2F)
		// have special meanings in JSON Pointer, '~' needs to be encoded as '~0'
		// and '/' needs to be encoded as '~1' when these characters appear in a
		// reference token."

		// RFC 6901 section 4: "Evaluation of each reference token begins by
		// decoding any escaped character sequence.  This is performed by first
		// transforming any occurrence of the sequence '~1' to '/', and then
		// transforming any occurrence of the sequence '~0' to '~'.  By performing
		// the substitutions in this order, an implementation avoids the error of
		// turning '~01' first into '~1' and then into '/', which would be
		// incorrect (the string '~01' correctly becomes '~1' after transformation)."
		path[i] = strings.Replace(path[i], "~1", "/", -1)
		path[i] = strings.Replace(path[i], "~0", "~", -1)
	}

	return
}
