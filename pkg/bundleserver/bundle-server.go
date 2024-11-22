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

// Package bundleserver provides functionalities for serving and building OPA bundles.
// This package includes functions to handle HTTP requests for bundles and
// to build OPA bundles using specified commands
package bundleserver

import (
	"net/http"
	"os"
	"os/exec"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"time"
)

// handles HTTP requests to serve the OPA bundle
func GetBundle(res http.ResponseWriter, req *http.Request) {
	log.Debugf("PDP received a Bundle request.")

	file, err := os.Open(consts.BundleTarGzFile)

	if err != nil {
		log.Warnf("Bundle server could not serve the request ::: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()

	res.Header().Set("Content-Type", "application/octet-stream")
	res.Header().Set("Content-Disposition", "attachment; filename="+consts.BundleTarGz)
	res.Header().Set("Content-Transfer-Encoding", "binary")
	res.Header().Set("Expires", "0")
	http.ServeContent(res, req, "Bundle Request Response", time.Now(), file)
}

// builds the OPA bundle using specified commands
func BuildBundle(cmdFunc func(string, ...string) *exec.Cmd) error {
	cmd := cmdFunc(consts.Opa, consts.BuildBundle, consts.V1_COMPATIBLE, consts.Policies, consts.Data, consts.Output, consts.BundleTarGzFile)
	log.Debugf("Before calling combinedoutput")
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Warnf("Error output : %s", string(output))
		log.Warnf("Failed to build Bundle: %v", err)
		return err
	}
	log.Debug("Bundle Built Sucessfully....")
	return nil
}
