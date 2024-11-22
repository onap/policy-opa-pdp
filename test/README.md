# Testing OPA

## Verification API Calls

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"example/allow","input":{"method":"POST","path":["users"]}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyName":"role/allow","input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

## PERMIT for policy:action

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"action/allow","input":{"user":"alice","action":"delete","type":"server"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"PERMIT","policyName":"action/allow","statusMessage":"OPA Allowed"}

## DENY for policy:action

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"action/allow","input":{"user":"charlie","action":"delete","type":"server"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"DENY","policyName":"action/allow","statusMessage":"OPA Denied"}

## PERMIT for policy:account

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC","timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"account/allow", "input":{"creditor_account":11111,"creditor":"alice","debtor_account":22222,"debtor":"bob","period":30,"amount":1000}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"PERMIT","policyName":"account/allow","statusMessage":"OPA Allowed"}

## DENY for policy:account

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"account/allow", "input":{"creditor_account":11111,"creditor":"alice","debtor_account":22222,"debtor":"bob","period":31,"amount":1000}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"DENY","policyName":"account/allow","statusMessage":"OPA Denied"}

## PERMIT for policy:organization

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"organization/allow", "input":{"user":"alice","action": "read","component": "component_A","project": "project_A", "organization": "org_A"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision
{"decision":"PERMIT","policyName":"organization/allow","statusMessage":"OPA Allowed"}

## DENY for policy:organization

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"organization/allow", "input":{"user":"charlie","action": "edit","component": "component_A","project": "project_A", "organization": "org_A"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"DENY","policyName":"organization/allow","statusMessage":"OPA Denied"}

## HealthCheck API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/healthcheck

{"code":200,"healthy":true,"message":"alive","name":"opa-9f0248ea-807e-45f6-8e0f-935e570b75cc","url":"self"}

## Statistics API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/statistics

{"code":200,"denyDecisionsCount":10,"deployFailureCount":0,"deploySuccessCount":0,"indeterminantDecisionsCount":0,"permitDecisionsCount":18,"totalErrorCount":4,"totalPoliciesCount":0,"totalPolicyTypesCount":1,"undeployFailureCount":0,"undeploySuccessCount":0}
