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

// The opasdk package provides functionalities for integrating with the Open Policy Agent
// (OPA) SDK, including reading configurations and managing a singleton OPA instance.
// This package is designed to ensure efficient, thread-safe initialization and configuration
// of the OPA instance.
package opasdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"sync"

	"github.com/open-policy-agent/opa/sdk"
)

// Define the structs
var (
	opaInstance *sdk.OPA  //A singleton instance of the OPA object
	once        sync.Once //A sync.Once variable used to ensure that the OPA instance is initialized only once,
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
		opaInstance, opaErr = sdk.New(context.Background(), sdk.Options{
			// Configure your OPA instance here
			V1Compatible: true,
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
