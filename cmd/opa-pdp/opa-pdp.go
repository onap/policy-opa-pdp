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

// Package main is the entry point for the policy-opa-pdp service.
// This package initializes the HTTP server, Kafka consumer and producer, and handles
// the overall service lifecycle including graceful shutdown
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	h "policy-opa-pdp/api"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/handler"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/pdpattributes"
	"syscall"
	"time"
)

var (
	bootstrapServers = cfg.BootstrapServer //The Kafka bootstrap server address.
	topic            = cfg.Topic           //The Kafka topic to subscribe to.
	patchTopic       = cfg.PatchTopic
	patchMsgProducer *kafkacomm.KafkaProducer
	patchMsgConsumer *kafkacomm.KafkaConsumer
	groupId          = cfg.GroupId
        patchGroupId     = cfg.PatchGroupId
)

// Declare function variables for dependency injection makes it more testable
var (
	initializeHandlersFunc         = initializeHandlers
	startHTTPServerFunc            = startHTTPServer
	shutdownHTTPServerFunc         = shutdownHTTPServer
	waitForServerFunc              = waitForServer
	initializeOPAFunc              = initializeOPA
	startKafkaConsAndProdFunc      = startKafkaConsAndProd
	handleMessagesFunc             = handleMessages
	handleShutdownFunc             = handleShutdown
	startPatchKafkaConsAndProdFunc = startPatchKafkaConsAndProd
	handlePatchMessagesFunc        = handlePatchMessages
)

// main function
func main() {
	var useKafkaForPatch = cfg.UseKafkaForPatch
	log.Debugf("Starting OPA PDP Service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Handlers and Build Bundle
	initializeHandlersFunc()

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
	sender := &publisher.RealPdpStatusSender{Producer: producer}

	// start pdp message handler in a seperate routine
	handleMessagesFunc(ctx, kc, sender)

	if useKafkaForPatch {
		patchMsgConsumer, patchMsgProducer, err := startPatchKafkaConsAndProdFunc()
		if err != nil || patchMsgConsumer == nil {
			log.Warnf("Kafka consumer initialization failed: %v", err)
		}
		log.Debugf("Producer initialized is: %v", patchMsgProducer)
		// start patch message handler in a seperate routine
		handlePatchMessagesFunc(ctx, patchMsgConsumer)
	}

	time.Sleep(10 * time.Second)

	pdpattributes.SetPdpHeartbeatInterval(int64(consts.DefaultHeartbeatMS))
	go publisher.StartHeartbeatIntervalTimer(pdpattributes.PdpHeartbeatInterval, sender)

	time.Sleep(10 * time.Second)
	log.Debugf("After registration successful delay")
	// Handle OS Interrupts and Graceful Shutdown
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	consumers := []*kafkacomm.KafkaConsumer{kc, patchMsgConsumer}
	producers := []*kafkacomm.KafkaProducer{producer, patchMsgProducer}
	handleShutdownFunc(consumers, interruptChannel, cancel, producers)
}

type PdpMessageHandlerFunc func(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string, p publisher.PdpStatusSender) error

var PdpMessageHandler PdpMessageHandlerFunc = handler.PdpMessageHandler

// starts pdpMessage Handler in a seperate routine which handles incoming messages on Kfka topic
func handleMessages(ctx context.Context, kc *kafkacomm.KafkaConsumer, sender *publisher.RealPdpStatusSender) {

	go func() {
		err := PdpMessageHandler(ctx, kc, topic, sender)
		if err != nil {
			log.Warnf("Erro in PdpUpdate Message Handler: %v", err)
		}
	}()
}

type PatchMessageHandlerFunc func(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string) error

var PatchMessageHandler PatchMessageHandlerFunc = handler.PatchMessageHandler

// starts patchMessage Handler in a seperate routine which handles incoming messages on Kfka topic
func handlePatchMessages(ctx context.Context, kc *kafkacomm.KafkaConsumer) {

	go func() {
		err := PatchMessageHandler(ctx, kc, patchTopic)
		if err != nil {
			log.Warnf("Erro in Patch Message Handler: %v", err)
		}
	}()
}

// Register Handlers
func initializeHandlers() {
	h.RegisterHandlers()
}

func startHTTPServer() *http.Server {
	//Configures the HTTP server to wait a maximum of 5 seconds for the headers of incoming requests
	server := &http.Server{Addr: consts.ServerPort, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %s", err)
		}
	}()
	return server
}

type ShutdownServFunc func(server *http.Server, ctx context.Context) error

var ShutdownServ ShutdownServFunc = (*http.Server).Shutdown

func shutdownHTTPServer(server *http.Server) {
	timeoutContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := ShutdownServ(server, timeoutContext); err != nil {
		log.Warnf("Failed to gracefully shut down server: %v", err)
	} else {
		log.Debug("Server shut down gracefully")
	}
}

func waitForServer() {
	time.Sleep(time.Duration(consts.ServerWaitUpTime) * time.Second)
}

func initializeOPA() error {
	opa, err := opasdk.GetOPASingletonInstance()
	if err != nil {
		return err
	}
	defer opa.Stop(context.Background())
	return nil
}

type NewKafkaConsumerFunc func(topic string, groupid string) (*kafkacomm.KafkaConsumer, error)

var NewKafkaConsumer NewKafkaConsumerFunc = kafkacomm.NewKafkaConsumer

type GetKafkaProducerFunc func(bootstrapServers string, topic string) (*kafkacomm.KafkaProducer, error)

var GetKafkaProducer GetKafkaProducerFunc = kafkacomm.GetKafkaProducer

func startKafkaConsAndProd() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
	log.Debugf("Topic start :::: %s", topic)
	kc, err := NewKafkaConsumer(topic, groupId)
	if err != nil {
		log.Warnf("Failed to create Kafka consumer: %v", err)
		return nil, nil, err
	}
	producer, err := GetKafkaProducer(bootstrapServers, topic)
	if err != nil {
		log.Warnf("Failed to create Kafka producer: %v", err)
		return nil, nil, err
	}
	return kc, producer, nil
}


func startPatchKafkaConsAndProd() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
	log.Debugf("Topic start :::: %s", patchTopic)
	kc, err := NewKafkaConsumer(patchTopic, patchGroupId)
	if err != nil {
		log.Warnf("Failed to create Kafka consumer: %v", err)
		return nil, nil, err
	}
	PatchProducer, err := GetKafkaProducer(bootstrapServers, patchTopic)
	if err != nil {
		log.Warnf("Failed to create Kafka producer: %v", err)
		return nil, nil, err
	}
	data.PatchProducer = PatchProducer
	return kc, PatchProducer, nil
}

func handleShutdown(consumers []*kafkacomm.KafkaConsumer, interruptChannel chan os.Signal, cancel context.CancelFunc, producers []*kafkacomm.KafkaProducer) {

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

	publisher.StopTicker()
	for _, producer := range producers {
		if producer != nil {
			producer.Close()
		}
	}

	for _, consumer := range consumers {
		if consumer == nil {
			log.Debugf("kc is nil so skipping")
			continue
		}

		if err := consumer.Consumer.Unsubscribe(); err != nil {
			log.Warnf("Failed to unsubscribe consumer: %v", err)
		} else {
			log.Debugf("Consumer Unsubscribed....")
		}
		if err := consumer.Consumer.Close(); err != nil {
			log.Debug("Failed to close consumer......")
		} else {
			log.Debugf("Consumer closed....")
		}
	}

	handler.SetShutdownFlag()

	time.Sleep(time.Duration(consts.ShutdownWaitTime) * time.Second)
}
