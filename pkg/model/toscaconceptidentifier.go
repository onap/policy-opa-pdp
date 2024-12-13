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

// Identifies a concept. Both the name and version must be non-null.
// https://github.com/onap/policy-models/blob/master/models-tosca
// models-tosca/src/main/java/org/onap/policy/models/tosca/authorative/concepts/ToscaConceptIdentifier.java
package model

import (
	"fmt"
)

type ToscaConceptIdentifier struct {
	Name    string
	Version string
}

func NewToscaConceptIdentifier(name, version string) *ToscaConceptIdentifier {
	return &ToscaConceptIdentifier{
		Name:    name,
		Version: version,
	}
}

func NewToscaConceptIdentifierFromKey(key PfKey) *ToscaConceptIdentifier {
	return &ToscaConceptIdentifier{
		Name:    key.Name,
		Version: key.Version,
	}
}

func (id *ToscaConceptIdentifier) ValidatePapRest() error {
	if id.Name == "" || id.Version == "" {
		return fmt.Errorf("name and version must be non-empty")
	}
	return nil
}

type PfKey struct {
	Name    string
	Version string
}
