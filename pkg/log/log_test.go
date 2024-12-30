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

package log_test

import (
	"testing"

	"bytes"
	"github.com/sirupsen/logrus"
	"policy-opa-pdp/pkg/log"
)

func TestSetOutput_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.InfoLevel)

	log.Info("Testing SetOutput")
	if !bytes.Contains(buf.Bytes(), []byte("Testing SetOutput")) {
		t.Errorf("Expected message to be logged")
	}
}

func TestInit_Success(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	log.InitLogger("/tmp/logfile.log", 10, 5, "debug")
	log.Info("Logger initialized")

	if !bytes.Contains(buf.Bytes(), []byte("Logger initialized")) {
		t.Errorf("Expected message to be logged after initialization")
	}
}

func TestInitLogger_Success(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)

	log.InitLogger("/tmp/logfile.log", 10, 5, "info")

	log.Info("Logger Initialized Test")
	if !bytes.Contains(buf.Bytes(), []byte("Logger Initialized Test")) {
		t.Errorf("Expected message to be logged")
	}
}

func TestParseLevel_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	level, err := logrus.ParseLevel("info")
	if err != nil {
		t.Fatalf("Failed to parse log level: %v", err)
	}
	log.SetLevel(level)

	log.Info("Info level set")

	if !bytes.Contains(buf.Bytes(), []byte("Info level set")) {
		t.Errorf("Expected info level to be set")
	}
}

func TestSetLevel_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel)

	log.Debug("This is a debug message")
	if !bytes.Contains(buf.Bytes(), []byte("This is a debug message")) {
		t.Errorf("Expected debug message to be logged")
	}
}

func TestError_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.ErrorLevel)

	log.Error("This is an error message")
	if !bytes.Contains(buf.Bytes(), []byte("This is an error message")) {
		t.Errorf("Expected error message to be logged")
	}
}

func TestInfo_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.InfoLevel)

	log.Info("This is an info message")
	if !bytes.Contains(buf.Bytes(), []byte("This is an info message")) {
		t.Errorf("Expected info message to be logged")
	}
}

func TestDebug_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel)

	log.Debug("This is a debug message")
	if !bytes.Contains(buf.Bytes(), []byte("This is a debug message")) {
		t.Errorf("Expected debug message to be logged")
	}
}

func TestWarn_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.WarnLevel)

	log.Warn("This is a warning message")
	if !bytes.Contains(buf.Bytes(), []byte("This is a warning message")) {
		t.Errorf("Expected warning message to be logged")
	}
}

func TestPanic_Success(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic, but did not get one")
		}
	}()

	log.SetLevel(logrus.PanicLevel)
	log.Panic("This is a panic message")
}

func TestTrace_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.TraceLevel)

	log.Trace("This is a trace message")
	if !bytes.Contains(buf.Bytes(), []byte("This is a trace message")) {
		t.Errorf("Expected trace message to be logged")
	}
}

func TestErrorf_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.ErrorLevel)

	log.Errorf("Error occurred: %s", "test error")
	if !bytes.Contains(buf.Bytes(), []byte("Error occurred: test error")) {
		t.Errorf("Expected error message to be logged")
	}
}

func TestInfof_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.InfoLevel)

	log.Infof("Info log: %s", "test info")
	if !bytes.Contains(buf.Bytes(), []byte("Info log: test info")) {
		t.Errorf("Expected info message to be logged")
	}
}

func TestDebugf_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel)

	log.Debugf("Debug message: %s", "should log")
	if !bytes.Contains(buf.Bytes(), []byte("Debug message: should log")) {
		t.Errorf("Expected debug message to be logged")
	}
}

func TestWarnf_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.WarnLevel)

	log.Warnf("Warning message: %s", "should log")
	if !bytes.Contains(buf.Bytes(), []byte("Warning message: should log")) {
		t.Errorf("Expected warning message to be logged")
	}
}

func TestPanicf_Success(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic, but did not get one")
		}
	}()

	log.SetLevel(logrus.PanicLevel)
	log.Panicf("Panic message: %s", "should panic")
}

func TestTracef_Success(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.TraceLevel)

	log.Tracef("Trace message: %s", "should log")
	if !bytes.Contains(buf.Bytes(), []byte("Trace message: should log")) {
		t.Errorf("Expected trace message to be logged")
	}
}

func TestError_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.FatalLevel) // Set level higher than Error

	log.Error("This is an error message")
	if bytes.Contains(buf.Bytes(), []byte("This is an error message")) {
		t.Errorf("Expected error message not to be logged")
	}
}

func TestInfo_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.WarnLevel) // Set level higher than Info

	log.Info("This is an info message")
	if bytes.Contains(buf.Bytes(), []byte("This is an info message")) {
		t.Errorf("Expected info message not to be logged")
	}
}

func TestDebug_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.InfoLevel) // Set level higher than Debug

	log.Debug("This is a debug message")
	if bytes.Contains(buf.Bytes(), []byte("This is a debug message")) {
		t.Errorf("Expected debug message not to be logged")
	}
}

func TestWarn_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.ErrorLevel) // Set level higher than Warn

	log.Warn("This is a warning message")
	if bytes.Contains(buf.Bytes(), []byte("This is a warning message")) {
		t.Errorf("Expected warning message not to be logged")
	}
}

func TestPanic_Failure(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic at PanicLevel, but did not get one")
		}
	}()
	log.SetLevel(logrus.PanicLevel) // Set to PanicLevel so a panic should occur
	log.Panic("This should cause a panic at PanicLevel")
}

func TestTrace_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel) // Set level higher than Trace

	log.Trace("This is a trace message")
	if bytes.Contains(buf.Bytes(), []byte("This is a trace message")) {
		t.Errorf("Expected trace message not to be logged")
	}
}

func TestErrorf_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.FatalLevel) // Set level higher than Error

	log.Errorf("Error occurred: %s", "test error")
	if bytes.Contains(buf.Bytes(), []byte("Error occurred: test error")) {
		t.Errorf("Expected error message not to be logged")
	}
}

func TestInfof_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.WarnLevel) // Set level higher than Info

	log.Infof("Info log: %s", "test info")
	if bytes.Contains(buf.Bytes(), []byte("Info log: test info")) {
		t.Errorf("Expected info message not to be logged")
	}
}

func TestDebugf_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.InfoLevel) // Set level higher than Debug

	log.Debugf("Debug message: %s", "should not log")
	if bytes.Contains(buf.Bytes(), []byte("Debug message: should not log")) {
		t.Errorf("Expected debug message not to be logged")
	}
}

func TestWarnf_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.ErrorLevel) // Set level higher than Warn

	log.Warnf("Warning message: %s", "should not log")
	if bytes.Contains(buf.Bytes(), []byte("Warning message: should not log")) {
		t.Errorf("Expected warning message not to be logged")
	}
}

func TestPanicf_Failure(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic at PanicLevel, but did not get one")
		}
	}()

	log.SetLevel(logrus.PanicLevel) // Set to PanicLevel so a panic should occur
	log.Panicf("Panicf message: %s", "should panic at PanicLevel")
}

func TestTracef_Failure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel) // Set level higher than Trace

	log.Tracef("Trace message: %s", "should not log")
	if bytes.Contains(buf.Bytes(), []byte("Trace message: should not log")) {
		t.Errorf("Expected trace message not to be logged")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input       string
		expectedErr bool
	}{
		{"DEBUG", false},
		{"INFO", false},
		{"WARN", false},
		{"ERROR", false},
		{"TRACE", false},
		{"PANIC", false},
		{"", true},        // Invalid input
		{"INVALID", true}, // Invalid input
	}

	for _, test := range tests {
		_, err := log.ParseLevel(test.input)
		if (err != nil) != test.expectedErr {
			t.Errorf("ParseLevel(%q) unexpected error state: got %v, want error: %v", test.input, err != nil, test.expectedErr)
		}
	}
}
