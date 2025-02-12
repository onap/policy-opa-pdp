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

	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// Define the structs
var (
	opaInstance *sdk.OPA  //A singleton instance of the OPA object
	once        sync.Once //A sync.Once variable used to ensure that the OPA instance is initialized only once,
	memStore    storage.Store
)

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

// Returns a singleton instance of the OPA object. The initialization of the instance is
// thread-safe, and the OPA object is configured using a JSON configuration file.
func GetOPASingletonInstance() (*sdk.OPA, error) {
	var err error
	once.Do(func() {
		var opaErr error
		memStore = inmem.New()
		opaInstance, opaErr = sdk.New(context.Background(), sdk.Options{
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

			opaInstance.Configure(context.Background(), sdk.ConfigOptions{
				Config: jsonReader,
			})
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
	res.Write([]byte("Check logs"))
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
