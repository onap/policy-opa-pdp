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

// Package consts provides constant values used throughout the policy-opa-pdp service.
// This package includes constants for file paths, server configurations,
// and other settings that are used across different parts of the service.
package consts

// Variables:
//
//			LogFilePath         - The file path for the log file.
//			LogMaxSize          - The maximum size of the log file in megabytes.
//			LogMaxBackups       - The maximum number of backup log files to retain.
//			OpasdkConfigPath    - The file path for the OPA SDK configuration.
//			Opa                 - The file path for the OPA binary.
//			BuildBundle         - The command to build the bundle.
//			Policies            - The directory path for policies.
//			Data                - The directory path for policy data.
//			DataNode            - The directory path for policy data with node.
//			Output              - The output flag for bundle commands.
//			BundleTarGz         - The name of the bundle tar.gz file.
//			BundleTarGzFile     - The file path for the bundle tar.gz file.
//			PdpGroup            - The default PDP group.
//			PdpType             - The type of PDP.
//			ServerPort          - The port on which the server listens.
//			ServerWaitUpTime    - The time to wait for the server to be up, in seconds.
//			ShutdownWaitTime    - The time to wait for the server to shut down, in seconds.
//			V1Compatible        - The flag for v1 compatibility.
//			LatestVersion       - The Version set in response for decision
//			MinorVersion        - The Minor version set in response header for decision
//			PatchVersion        - The Patch Version set in response header for decison
//			OpaPdpUrl           - The Healthcheck url for response
//			HealtCheckStatus    - The bool flag for Healthy field in HealtCheck response
//			OkCode              - The Code for HealthCheck response
//			HealthCheckMessage  - The Healtcheck Message
//		        DefaultHeartbeatMS  - The default interval for heartbeat signals in milliseconds.
//			SingleHierarchy     - The Counter indicates the length of datakey path
//		        PolicyVersion       - constant declared for policy-version
//		        PolicyID            - constant declared for policy-id
//		        RequestId           - constant declared for ONAP Request-ID
//	             MaxOutputResponseLength - constant declared for maximum length of output in response message
//	             ContentType              - constant for response Content Type
var (
	LogFilePath             = "/var/logs/logs.log"
	LogMaxSize              = 10
	LogMaxBackups           = 3
	OpasdkConfigPath        = "/app/config/config.json"
	Opa                     = "/app/opa"
	BuildBundle             = "build"
	Policies                = "/opt/policies"
	Data                    = "/opt/data"
	DataNode                = "/opt/data/node"
	Output                  = "-o"
	BundleTarGz             = "bundle.tar.gz"
	BundleTarGzFile         = "/app/bundles/bundle.tar.gz"
	PdpGroup                = "opaGroup"
	PdpType                 = "opa"
	ServerPort              = ":8282"
	ServerWaitUpTime        = 5
	ShutdownWaitTime        = 5
	V1Compatible            = "--v1-compatible"
	LatestVersion           = "1.0.0"
	MinorVersion            = "0"
	PatchVersion            = "0"
	OpaPdpUrl               = "self"
	HealtCheckStatus        = true
	OkCode                  = int32(200)
	HealthCheckMessage      = "alive"
	DefaultHeartbeatMS      = 60000
	SingleHierarchy         = 4
	PolicyVersion           = "policy-version"
	PolicyId                = "policy-id"
	RequestId               = "X-ONAP-RequestID"
	MaxOutputResponseLength = 200
	ContentType             = "Content-Type"
	ApplicationJson         = "application/json"
)
