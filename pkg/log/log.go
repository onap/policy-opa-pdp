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
//

package log

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
)

type Logger struct {
	*logrus.Logger
}

var (
	Log *Logger
)

func SetOutput(w io.Writer) {
	Log.SetOutput(w)
}

func init() {
	Log = InitLogger(consts.LogFilePath, consts.LogMaxSize, consts.LogMaxBackups, cfg.LogLevel)
}

func InitLogger(logFilePath string, logMaxSize int, logMaxBackups int, logLevel string) *Logger {
	log := logrus.New()

	log.SetLevel(logrus.DebugLevel)
	log.SetOutput(os.Stdout)

	logLevelParsed, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Warn(err)
	}
	log.SetLevel(logLevelParsed)

	logRotation := &lumberjack.Logger{
		Filename:   consts.LogFilePath,
		MaxSize:    consts.LogMaxSize,
		MaxBackups: consts.LogMaxBackups,
	}
	multiWriter := io.MultiWriter(os.Stdout, logRotation)
	log.SetOutput(multiWriter)

	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.0000-07:00",
	})

	log.Debugf("logger initialised Filepath = %s, Logsize(MB) = %d, Backups = %d, Loglevel = %s", logFilePath, logMaxSize, logMaxBackups, logLevel)
	return &Logger{log}
}

func ParseLevel(level string) (logrus.Level, error) {
	return logrus.ParseLevel(level)
}

func SetLevel(level logrus.Level) {
	Log.SetLevel(level)
}

func Error(args ...interface{}) {
	Log.Error(args...)
}

func Info(args ...interface{}) {
	Log.Info(args...)
}

func Debug(args ...interface{}) {
	Log.Debug(args...)
}

func Warn(args ...interface{}) {
	Log.Warn(args...)
}

func Panic(args ...interface{}) {
	Log.Panic(args...)
}

func Trace(args ...interface{}) {
	Log.Trace(args...)
}

func Errorf(msg string, args ...interface{}) {
	Log.Errorf(msg, args...)
}

func Infof(msg string, args ...interface{}) {
	Log.Infof(msg, args...)
}

func Debugf(msg string, args ...interface{}) {
	Log.Debugf(msg, args...)
}

func Warnf(msg string, args ...interface{}) {
	Log.Warnf(msg, args...)
}

func Panicf(msg string, args ...interface{}) {
	Log.Panicf(msg, args...)
}

func Tracef(msg string, args ...interface{}) {
	Log.Tracef(msg, args...)
}
