// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2026: Deutsche Telekom
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

package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/compile"
)

// ParseAST returns the AST of regoCode as JSON.
//
// This is the in-process equivalent of `opa parse --format=json`: that command marshals the
// very same *ast.Module. Because no file is involved the module is named after the file the
// deploy path would have written it to, so parse errors quote a stable name.
func ParseAST(regoCode string) (json.RawMessage, error) {
	log.Debugf("ParseAST input (truncated): %.128s", regoCode)

	module, err := ast.ParseModuleWithOpts(consts.StandardPolicyName, regoCode, ast.ParserOptions{
		ProcessAnnotation: true,
		RegoVersion:       ast.RegoV1,
	})
	if err != nil {
		log.Errorf("OPA parse failed: %v", err)
		return nil, fmt.Errorf("failed to parse policy: %v", err)
	}

	astJSON, err := json.MarshalIndent(module, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy AST: %w", err)
	}

	return astJSON, nil
}

// BuildBundle compiles every policy and data file staged under consts.Policies and
// consts.Data, which is how a freshly written policy is proven valid before it is upserted
// into the OPA store.
//
// In-process equivalent of `opa build --v1-compatible /opt/policies /opt/data -o <file>`.
// No output writer is configured because nothing ever read the resulting archive — only the
// compile errors matter.
func BuildBundle() error {
	err := compile.New().
		WithPaths(consts.Policies, consts.Data).
		WithRegoVersion(ast.RegoV1).
		Build(context.Background())
	if err != nil {
		log.Warnf("Failed to build Bundle: %v", err)
		return err
	}

	log.Debug("Bundle built successfully")
	return nil
}
