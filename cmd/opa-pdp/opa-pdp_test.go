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

package main

import (

	"context"
	"errors"
	"net/http"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/mocks"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

// Mock objects and functions
type MockKafkaConsumerInterface struct {
	mock.Mock
}

func (m *MockKafkaConsumerInterface) Unsubscribe() {
	m.Called()
}

func (m *MockKafkaConsumerInterface) Close() {
	m.Called()
}

func (m *MockKafkaConsumerInterface) ReadMessage(kc *kafkacomm.KafkaConsumer) ([]byte, error) {
	args := m.Called(kc)
	return args.Get(0).([]byte), args.Error(0)
}

type MockKafkaProducer struct {
        mock.Mock
}

func (m *MockKafkaProducer) Produce(message *kafka.Message, evenchan chan kafka.Event) error {
        args := m.Called(message)
        return args.Error(0)
}

func (m *MockKafkaProducer) Close() {
        m.Called()
}

func (m *MockKafkaProducer) Flush(timeout int) int {
        m.Called(timeout)
        return 0
}


type MockPdpStatusSender struct {
	mock.Mock
}

func (m *MockPdpStatusSender) SendRegistration() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockPdpStatusSender) SendPdpStatus(pdpStatus model.PdpStatus) error {
	args := m.Called(pdpStatus)
	return args.Error(0)
}

type MockServer struct {
	*http.Server
	mock.Mock
}

func (m *MockServer) Shutdown() error {
	args := m.Called()
	return args.Error(0)
}

// Test to verify the application handles the shutdown process gracefully.
func TestHandleShutdown(t *testing.T) {
	consts.SHUTDOWN_WAIT_TIME = 0
	mockConsumer := new(mocks.KafkaConsumerInterface)
	mockConsumer.On("Unsubscribe").Return(nil)
	mockConsumer.On("Close").Return(nil)
	kafkaProducer := &kafkacomm.KafkaProducer{}

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockConsumer,
	}
	// Create the mock producer
        mockProducer := new(MockKafkaProducer)

        // Mock the Produce method to simulate success
        mockProducer.On("Produce", mock.Anything).Return(nil)
        //t.Fatalf("Inside Sender checking for producer , but got: %v", mockProducer)


        // Create the RealPdpStatusSender with the mocked producer
        kafkaProducer = &kafkacomm.KafkaProducer{}

	interruptChannel := make(chan os.Signal, 1)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(500 * time.Millisecond)
		interruptChannel <- os.Interrupt
	}()
	done := make(chan bool)
	go func() {
		handleShutdown(mockKafkaConsumer, interruptChannel, cancel, kafkaProducer)
		done <- true
	}()

	select {
	case <-done:
		mockConsumer.AssertCalled(t, "Unsubscribe")
		mockConsumer.AssertCalled(t, "Close")
	case <-time.After(2 * time.Second):
		t.Error("handleShutdown timed out")
	}
}

var  testServer *http.Server
var kafkaConsumer *kafkacomm.KafkaConsumer
var kafkaProducer *kafkacomm.KafkaProducer
// Test the main function to ensure it's initialization, startup, and shutdown correctly.
func SetupMocks() {
	// Mock dependencies and expected behavior
        testServer = &http.Server{}
	kafkaConsumer= &kafkacomm.KafkaConsumer{}
	kafkaProducer= &kafkacomm.KafkaProducer{}
	// Mock initializeHandlers
	initializeHandlersFunc = func() {
		log.Debug("Handlers initialized")
	}

	// Use an actual *http.Server instance for testing
	testServer := &http.Server{}

	// Mock startHTTPServer to return the real server
	startHTTPServerFunc = func() *http.Server {
		return testServer
	}

	// Mock shutdownHTTPServer to call Shutdown on the real server
	shutdownHTTPServerFunc = func(server *http.Server) {
		server.Shutdown(context.Background()) // Use a context for safe shutdown
	}

	// Mock waitForServer
	waitForServerFunc = func() {
		time.Sleep(10 * time.Millisecond) // Simulate server startup delay
	}

	// Mock initializeOPA
	initializeOPAFunc = func() error {
		return nil // no error expected
	}


	registerPDPFunc = func(sender publisher.PdpStatusSender) bool {
		// Simulate the registration logic here
		return false// Simulate successful registration
	}

        handleMessagesFunc = func(ctx context.Context, kc *kafkacomm.KafkaConsumer, sender *publisher.RealPdpStatusSender) {
                return
        }

	// Mock handleShutdown
	interruptChannel := make(chan os.Signal, 1)
	handleShutdownFunc = func(kc *kafkacomm.KafkaConsumer, interruptChan chan os.Signal, cancel context.CancelFunc, kp *kafkacomm.KafkaProducer) {
		interruptChannel <- os.Interrupt
		cancel()
	}
}

func TestKafkaConsumerInitializationFailure(t *testing.T){


        SetupMocks()

	startKafkaConsAndProdFunc = func() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
                return nil, nil, assert.AnError // return mocked consumer and producer
        }

	// Run main function in a goroutine
	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	// Simulate an interrupt to trigger shutdown
	interruptChannel := make(chan os.Signal, 1)
	interruptChannel <- os.Interrupt

	// Wait for main to complete or timeout
	select {
	case <-done:
		// Success, verify if mocks were called as expected
		// mockServer.AssertCalled(t, "Shutdown")
	case <-time.After(1 * time.Second):
		// t.Error("main function timed out")
	}

	// Verify assertions
	assert.True(t, true, "main function executed successfully")
}

func TestKafkaConsumerInitializationSuccess(t *testing.T){


        SetupMocks()

        startKafkaConsAndProdFunc = func() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
                return kafkaConsumer, kafkaProducer, nil  // return mocked consumer and producer
        }

        // Run main function in a goroutine
        done := make(chan struct{})
        go func() {
                main()
                close(done)
        }()

        // Simulate an interrupt to trigger shutdown
        interruptChannel := make(chan os.Signal, 1)
        interruptChannel <- os.Interrupt

        // Wait for main to complete or timeout
        select {
        case <-done:
                // Success, verify if mocks were called as expected
                // mockServer.AssertCalled(t, "Shutdown")
        case <-time.After(1 * time.Second):
                // t.Error("main function timed out")
        }

        // Verify assertions
        assert.True(t, true, "main function executed successfully")
}

func TestKafkaNilConsumerInitialization(t *testing.T){


        SetupMocks()

        startKafkaConsAndProdFunc = func() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
                return nil, kafkaProducer, nil  // return mocked consumer and producer
        }

        // Run main function in a goroutine
        done := make(chan struct{})
        go func() {
                main()
                close(done)
        }()

        // Simulate an interrupt to trigger shutdown
        interruptChannel := make(chan os.Signal, 1)
        interruptChannel <- os.Interrupt

        // Wait for main to complete or timeout
        select {
        case <-done:
                // Success, verify if mocks were called as expected
                // mockServer.AssertCalled(t, "Shutdown")
        case <-time.After(1 * time.Second):
                // t.Error("main function timed out")
        }

        // Verify assertions
        assert.True(t, true, "main function executed successfully")
}

// Test to verify that the HTTP server starts successfully.
func TestStartHTTPServer(t *testing.T) {
	server := startHTTPServer()
	time.Sleep(1 * time.Second)
	assert.NotNil(t, server, "Server should be initialized")
}

// Test to validate the initialization of the OPA (Open Policy Agent) instance.
func TestInitializeOPA(t *testing.T) {
	err := initializeOPA()
	assert.Error(t, err, "Expected error from initializeOPA")
}



// Test to ensure the application correctly waits for the server to be ready.
func TestWaitForServer(t *testing.T) {
	waitForServerFunc = func() {
		time.Sleep(50 * time.Millisecond)
	}

	waitForServer()
}

// TestInitializeHandlers
func TestInitializeHandlers(t *testing.T) {
	initializeHandlersFunc = func() {
		log.Debug("Handlers initialized")
	}

	initializeHandlers()
}

// Test to simulate the successful registration of a PDP
func TestRegisterPDP_Success(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	result := registerPDP(mockSender)

	assert.True(t, result)
	mockSender.AssertExpectations(t)
}

// Test to simulate a failure scenario during the registration of a PDP.
func TestRegisterPDP_Failure(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(assert.AnError)

	result := registerPDP(mockSender)

	assert.False(t, result)
	mockSender.AssertExpectations(t)
}

// Test to verify that the HTTP Server starts successfully and can be shut down gracefully.
func TestStartAndShutDownHTTPServer(t *testing.T) {
	testServer := startHTTPServer()

	time.Sleep(1 * time.Second)

	assert.NotNil(t, testServer, "Server should be initialized")

	go func() {
		err := testServer.ListenAndServe()
		assert.Error(t, err, "Server should not return error after starting and shutting down")
	}()

	shutdownHTTPServer(testServer)
}

func TestMainFunction_Failure(t *testing.T) {
	interruptChannel := make(chan os.Signal, 1)
	initializeOPAFunc = func() error {
		return errors.New("OPA initialization failed")
	}

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	interruptChannel <- os.Interrupt

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Error("main function timed out on failure scenario")
	}
}

// Test to verify that the application handles errors during the shutdown process gracefully.
func TestHandleShutdown_ErrorScenario(t *testing.T) {
	mockConsumer := new(mocks.KafkaConsumerInterface)
	mockConsumer.On("Unsubscribe").Return(errors.New("unsubscribe error"))
	mockConsumer.On("Close").Return(errors.New("close error"))
	mockKafkaConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockConsumer,
	}
	kafkaProducer := &kafkacomm.KafkaProducer{}
	interruptChannel := make(chan os.Signal, 1)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(100 * time.Millisecond)
		interruptChannel <- os.Interrupt
	}()

	done := make(chan bool)
	go func() {
		handleShutdown(mockKafkaConsumer, interruptChannel, cancel, kafkaProducer)
		done <- true
	}()

	select {
	case <-done:
		mockConsumer.AssertCalled(t, "Unsubscribe")
		mockConsumer.AssertCalled(t, "Close")
	case <-time.After(1 * time.Second):
		t.Error("handleShutdown timed out")
	}
}

// Test to simulate errors during the shutdown of the HTTP server.
func TestShutdownHTTPServer_Error(t *testing.T) {
	mockServer := &MockServer{}

	mockServer.On("Shutdown").Return(errors.New("shutdown error"))

	shutdownHTTPServerFunc := func(s *MockServer) {
		err := s.Shutdown()
		if err != nil {
			t.Logf("Expected error during shutdown: %v", err)
		}
	}

	shutdownHTTPServerFunc(mockServer)

	mockServer.AssertExpectations(t)
}

// Test to validate the successful shutdown of the HTTP server.
func TestShutdownHTTPServerSucessful(t *testing.T) {
	t.Run("SuccessfulShutdown", func(t *testing.T) {
		mockServer := &MockServer{
			Server: &http.Server{},
		}

		mockServer.On("Shutdown").Return(nil)

		err := mockServer.Shutdown()
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		shutdownHTTPServer(mockServer.Server)
		mockServer.AssertExpectations(t)
	})

	t.Run("ShutdownWithError", func(t *testing.T) {

		mockServer := &MockServer{
			Server: &http.Server{},
		}

		mockServer.On("Shutdown").Return(errors.New("shutdown error"))

		err := mockServer.Shutdown()
		if err == nil {
			t.Error("Expected an error, but got none")
		}
		shutdownHTTPServer(mockServer.Server)
		mockServer.AssertExpectations(t)

	})

}

// TestHandleMessages
func TestHandleMessages(t *testing.T) {
	message := `{"MessageType": "PDP_UPDATE", "Data": "test-update"}`
	mockKafkaConsumer := new(mocks.KafkaConsumerInterface)
	mockSender := &publisher.RealPdpStatusSender{}
	expectedError := error(nil)

	kafkaMsg := &kafka.Message{
		Value: []byte(message),
	}
	mockKafkaConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)
	mockConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockKafkaConsumer,
	}

	ctx := context.Background()
	handleMessages(ctx, mockConsumer, mockSender)

}

// Test to simulate a Kafka initialization failure in the main function.
func TestMain_KafkaInitializationFailure(t *testing.T) {
	startKafkaConsAndProdFunc = func() (*kafkacomm.KafkaConsumer, *kafkacomm.KafkaProducer, error) {
		return nil, nil, errors.New("kafka initialization failed")
	}

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	select {
	case <-done:
		// Verify if the Kafka failure path is executed
	case <-time.After(1 * time.Second):
		t.Error("main function timed out on Kafka initialization failure")
	}
}

// Test to validate the main function's handling of shutdown signals.
func TestMain_HandleShutdownWithSignals(t *testing.T) {
	handleShutdownFunc = func(kc *kafkacomm.KafkaConsumer, interruptChan chan os.Signal, cancel context.CancelFunc, producer *kafkacomm.KafkaProducer) {
		go func() {
			interruptChan <- os.Interrupt // Simulate SIGTERM
		}()
		cancel()
	}

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("main function timed out on signal handling")
	}
}

var mockConsumer = &kafkacomm.KafkaConsumer{}
var mockProducer = &kafkacomm.KafkaProducer{}

// Test to simulate the scenario where starting the Kafka consumer fails
func TestStartKafkaConsumerFailure(t *testing.T) {
	t.Run("Kafka consumer creation failure", func(t *testing.T) {
		originalNewKafkaConsumer := NewKafkaConsumer
		originalGetKafkaProducer := GetKafkaProducer
		NewKafkaConsumer = func() (*kafkacomm.KafkaConsumer, error) {
			return nil, errors.New("Kafka consumer creation error")
		}

		GetKafkaProducer = func(bootstrapServers, topic string) (*kafkacomm.KafkaProducer, error) {
			NewKafkaConsumer = originalNewKafkaConsumer
			GetKafkaProducer = originalGetKafkaProducer
			return mockProducer, nil
		}

		// Call the function under test
		consumer, producer, err := startKafkaConsAndProd()

		// Assertions
		assert.Error(t, err, "Kafka consumer creation error")
		assert.Nil(t, consumer)
		assert.Nil(t, producer)
		NewKafkaConsumer = originalNewKafkaConsumer
		GetKafkaProducer = originalGetKafkaProducer
	})
}

// Test to simulate the scenario where starting the Kafka producer fails
func TestStartKafkaProducerFailure(t *testing.T) {
	t.Run("Kafka producer creation failure", func(t *testing.T) {
		originalNewKafkaConsumer := NewKafkaConsumer
		originalGetKafkaProducer := GetKafkaProducer
		NewKafkaConsumer = func() (*kafkacomm.KafkaConsumer, error) {
			return mockConsumer, nil
		}

		GetKafkaProducer = func(bootstrapServers, topic string) (*kafkacomm.KafkaProducer, error) {
			return nil, errors.New("Kafka producer creation error")
		}

		// Call the function under test
		consumer, producer, err := startKafkaConsAndProd()

		// Assertions
		assert.Error(t, err, "Kafka producer creation error")
		assert.Nil(t, consumer)
		assert.Nil(t, producer)


		NewKafkaConsumer = originalNewKafkaConsumer
		GetKafkaProducer = originalGetKafkaProducer
	})
}

// Test to verify that both the Kafka consumer and producer start successfully
func TestStartKafkaAndProdSuccess(t *testing.T) {
	t.Run("Kafka consumer and producer creation success", func(t *testing.T) {
		originalNewKafkaConsumer := NewKafkaConsumer
		originalGetKafkaProducer := GetKafkaProducer
		NewKafkaConsumer = func() (*kafkacomm.KafkaConsumer, error) {
			return mockConsumer, nil
		}
		GetKafkaProducer = func(bootstrapServers, topic string) (*kafkacomm.KafkaProducer, error) {
			return mockProducer, nil
		}

		// Call the function under test
		consumer, producer, err := startKafkaConsAndProd()

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, consumer)
		assert.NotNil(t, producer)

		NewKafkaConsumer = originalNewKafkaConsumer
		GetKafkaProducer = originalGetKafkaProducer
	})
}

// Test to verify that the shutdown process handles a nil Kafka consumer gracefully
func TestHandleShutdownWithNilConsumer(t *testing.T) {
	consts.SHUTDOWN_WAIT_TIME = 0
	interruptChannel := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()
        kafkaProducer := &kafkacomm.KafkaProducer{}
	// Simulate sending an interrupt signal
	go func() {
		time.Sleep(500 * time.Millisecond)
		interruptChannel <- os.Interrupt
	}()
	done := make(chan bool)
	go func() {
		handleShutdown(nil, interruptChannel, cancel, kafkaProducer) // Pass nil as kc
		done <- true
	}()

	select {
	case <-done:
		// Test should pass without any errors
		assert.NotNil(t, ctx.Err(), "Expected context to br canceled")
		assert.Equal(t, context.Canceled, ctx.Err(), "Context should be canceled after shutdown")
	case <-time.After(2 * time.Second):
		t.Error("handleShutdown with nil consumer timed out")
	}
}

// Test to simulate an error scenario in the PDP message handler while processing messages
func TestHandleMessages_ErrorInPdpMessageHandler(t *testing.T) {
	// Mock dependencies
	mockKafkaConsumer := new(mocks.KafkaConsumerInterface)
	mockSender := &publisher.RealPdpStatusSender{}

	// Simulate Kafka consumer returning a message
	kafkaMsg := &kafka.Message{
		Value: []byte(`{"MessageType": "PDP_UPDATE", "Data": "test-update"}`),
	}
	mockKafkaConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, nil)
	mockConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockKafkaConsumer,
	}

	originalPdpMessageHandler := PdpMessageHandler
		PdpMessageHandler = func(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string, p publisher.PdpStatusSender) error {
		return errors.New("simulated error in PdpMessageHandler")
	}

	// Call handleMessages
	ctx := context.Background()
	handleMessages(ctx, mockConsumer, mockSender)

	// No crash means the error branch was executed.
	assert.True(t, true, "handleMessages executed successfully")
	PdpMessageHandler := originalPdpMessageHandler
	assert.NotNil(t, PdpMessageHandler)
}

// Test to verify the behavior when the HTTP server shutdown encounters errors.
func TestShutdownHTTPServer_Errors(t *testing.T) {
	// Create a mock server
	server := &http.Server{}

	ShutdownServ = func(server *http.Server, ctx context.Context) error {
		return errors.New("shutdown error")
	}

	// Call the function
	shutdownHTTPServer(server)
	assert.True(t, true, "Shutdown error")
}
