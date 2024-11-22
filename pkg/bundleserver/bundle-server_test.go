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

package bundleserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"policy-opa-pdp/consts"
	"testing"
)

// Mock function for exec.Command
func mockCmd(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess is a helper process used by mockCmd
func TestHelperProcess(*testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	os.Exit(0)
}

func TestGetBundle(t *testing.T) {
	// Create a temporary file to simulate the bundle file
	tmpFile, err := os.CreateTemp("", "bundle-*.tar.gz")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	consts.BundleTarGzFile = tmpFile.Name()

	req, err := http.NewRequest("GET", "/bundle", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(GetBundle)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "attachment; filename=" + consts.BundleTarGz
	if rr.Header().Get("Content-Disposition") != expected {
		t.Errorf("handler returned unexpected header: got %v want %v", rr.Header().Get("Content-Disposition"), expected)
	}
}

func TestGetBundle_FileNotFound(t *testing.T) {
	consts.BundleTarGzFile = "nonexistent-file.tar.gz"

	req, err := http.NewRequest("GET", "/bundle", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(GetBundle)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}
}

func TestBuildBundle(t *testing.T) {
	err := BuildBundle(mockCmd)
	if err != nil {
		t.Errorf("BuildBundle() error = %v, wantErr %v", err, nil)
	}
}

func TestBuildBundle_CommandFailure(t *testing.T) {
	// Mock function to simulate command failure
	mockCmdFail := func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
		cmd.Stderr = os.Stderr
		return cmd
	}

	err := BuildBundle(mockCmdFail)
	if err == nil {
		t.Errorf("BuildBundle() error = nil, wantErr %v", "command failure")
	}
}
