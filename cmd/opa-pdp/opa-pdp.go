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

// Package main is the entry point for the policy-opa-pdp service.
// This package initializes the HTTP server, Kafka consumer and producer, and handles
// the overall service lifecycle including graceful shutdown
package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	h "policy-opa-pdp/api"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/bundleserver"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/handler"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/opasdk"
	"syscall"
	"time"
)

var (
	bootstrapServers = cfg.BootstrapServer //The Kafka bootstrap server address.
	topic            = cfg.Topic           //The Kafka topic to subscribe to.
)

// Declare function variables for dependency injection makes it more testable
var (
	initializeHandlersFunc    = initializeHandlers
	initializeBundleFunc      = initializeBundle
	startHTTPServerFunc       = startHTTPServer
	shutdownHTTPServerFunc    = shutdownHTTPServer
	waitForServerFunc         = waitForServer
	initializeOPAFunc         = initializeOPA
	startKafkaConsAndProdFunc = startKafkaConsAndProd
	registerPDPFunc           = registerPDP
	handleMessagesFunc        = handleMessages
	handleShutdownFunc        = handleShutdown
)

// main function
func main() {
	log.Debugf("Starting OPA PDP Service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Handlers and Build Bundle
	initializeHandlersFunc()
	if err := initializeBundleFunc(exec.Command); err != nil {
		log.Warnf("Failed to initialize bundle: %s", err)
	}

	// Start HTTP Server
	server := startHTTPServerFunc()
	defer shutdownHTTPServerFunc(server)

	// Wait for server to be up
	waitForServerFunc()
	log.Info("HTTP server started")

	// Initialize OPA components

	if err := initializeOPAFunc(); err != nil {
		log.Errorf("OPA initialization failed: %s", err)
		return
	}

	// Start Kafka Consumer and producer
	kc, producer, err := startKafkaConsAndProdFunc()
	if err != nil || kc == nil {
		log.Warnf("Kafka consumer initialization failed: %v", err)
	}
	defer producer.Close()

	sender := &publisher.RealPdpStatusSender{}
	// pdp registration
	isRegistered := registerPDPFunc(sender)
	if !isRegistered {
		return
	}

	// start pdp message handler in a seperate routine
	handleMessagesFunc(ctx, kc, sender)

	// Handle OS Interrupts and Graceful Shutdown
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	handleShutdownFunc(kc, interruptChannel, cancel)
}

// starts pdpMessage Handler in a seperate routine which handles incoming messages on Kfka topic
func handleMessages(ctx context.Context, kc *kafkacomm.KafkaConsumer, sender *publisher.RealPdpStatusSender) {

	go func() {
		err := handler.PdpMessageHandler(ctx, kc, topic, sender)
		if err != nil {
			log.Warnf("Erro in PdpUpdate Message Handler: %v", err)
		}
	}()
}

// register pdp with PAP
func registerPDP(sender publisher.PdpStatusSender) bool {
	if err := publisher.SendPdpPapRegistration(sender); err != nil {
		log.Warnf("Failed PDP PAP registration: %v", err)
		return false
	}
	log.Debugf("PDP PAP registration successful")
	return true
}

// Register Handlers
func initializeHandlers() {
	h.RegisterHandlers()
}

// build bundle tar file
func initializeBundle(execCmd func(string, ...string) *exec.Cmd) error {
	return bundleserver.BuildBundle(execCmd)
}

func startHTTPServer() *http.Server {
	server := &http.Server{Addr: consts.ServerPort}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %s", err)
		}
	}()
	return server
}

func shutdownHTTPServer(server *http.Server) {
	timeoutContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(timeoutContext); err != nil {
		log.Warnf("Failed to gracefully shut down server: %v", err)
	} else {
		log.Debug("Server shut down gracefully")
	}
}

func waitForServer() {
	time.Sleep(time.Duration(consts.SERVER_WAIT_UP_TIME) * time.Second)
}

func initializeOPA() error {
	opa, err := opasdk.GetOPASingletonInstance()
	if err != nil {
		return err
	}
	defer opa.Stop(context.Background())
	return nil
}

func startKafkaConsAndProd() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
	kc, err := kafkacomm.NewKafkaConsumer()
	if err != nil {
		log.Warnf("Failed to create Kafka consumer: %v", err)
		return nil, nil, err
	}
	producer, err := kafkacomm.GetKafkaProducer(bootstrapServers, topic)
	if err != nil {
		log.Warnf("Failed to create Kafka producer: %v", err)
		return nil, nil, err
	}
	return kc, producer, nil
}

func handleShutdown(kc *kafkacomm.KafkaConsumer, interruptChannel chan os.Signal, cancel context.CancelFunc) {

myLoop:
	for {
		select {
		case <-interruptChannel:
			log.Debugf("Received Termination Signal.......")
			break myLoop
		}
	}
	cancel()
	log.Debugf("Loop Exited and shutdown started")
	signal.Stop(interruptChannel)

	if kc == nil {
		log.Debugf("kc is nil so skipping")
		return
	}

	if err := kc.Consumer.Unsubscribe(); err != nil {
		log.Warnf("Failed to unsubscribe consumer: %v", err)
	} else {
		log.Debugf("Consumer Unsubscribed....")
	}
	if err := kc.Consumer.Close(); err != nil {
		log.Debug("Failed to close consumer......")
	} else {
		log.Debugf("Consumer closed....")
	}

	handler.SetShutdownFlag()
	publisher.StopTicker()

	time.Sleep(time.Duration(consts.SHUTDOWN_WAIT_TIME) * time.Second)
}
