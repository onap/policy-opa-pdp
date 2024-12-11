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

## DENY for policy:abac(output)

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"abac", "policyFilter": ["action_is_read"], "input":{"actions": ["write"],"datatypes": ["location","temperature","precipitation","windspeed"],"time_period": {"from": "2024-03-27","to": "2024-03-31"}}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision
{"decision":"DENY","output":{},"policyName":"abac","statusMessage":"OPA Denied"}

## PERMIT for policy:abac

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"abac", "policyFilter": ["viewable_sensor_data"], "input":{"actions": ["read"],"datatypes": ["location","temperature","precipitation","windspeed"],"time_period": {"from": "2024-02-27","to": "2024-02-29"}}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision
{"decision":"PERMIT","output":{"viewable_sensor_data":[{"location":"Galle","precipitation":"500 mm","temperature":"35 C","windspeed":"7.2 m/s"},{"location":"Jaffna","precipitation":"300 mm","temperature":"-5 C","windspeed":"3.8 m/s"},{"location":"Nuwara Eliya","precipitation":"600 mm","temperature":"25 C","windspeed":"4.0 m/s"},{"location":"Trincomalee","precipitation":"1000 mm","temperature":"20 C","windspeed":"5.0 m/s"}]},"policyName":"abac","statusMessage":"OPA Allowed"}

## PERMIT for policy:zone
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"zone", "policyFilter": ["has_zone_access"], "input":{"actions": ["view"],"log_id": "log1", "datatypes": ["access", "user"],"time_period": {"from": "2024-11-01T09:00:00Z","to": "2024-11-01T10:00:00Z"},"zone_id": "zoneA"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision
{"decision":"PERMIT","output":{"has_zone_access":[{"access":"granted","user":"user1"}]},"policyName":"zone","statusMessage":"OPA Allowed"}

## DENY for policy: zone

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"zone", "policyFilter": ["has_zone_access"], "input":{"actions": ["edit"],"log_id": "log1", "datatypes": ["access", "user"],"time_period": {"from": "2024-11-01T00:00:00Z","to": "2024-11-01T00:00:00Z"},"zone_id": "zoneA"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision
{"decision":"DENY","output":{"has_zone_access":[]},"policyName":"zone","statusMessage":"OPA Denied"}

## PERMIT for policy:vehicle

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"vehicle", "policyFilter": ["user_has_vehicle_access"], "input":{"actions": ["use"],"user":"user1", "vehicle_id": "v1", "attributes": ["type", "status"]}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"PERMIT","output":{"user_has_vehicle_access":[{"status":"available","type":"car"}]},"policyName":"vehicle","statusMessage":"OPA Allowed"}

## PERMIT for policy:docs

`curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"docs", "policyFilter": ["has_access_to_file"], "input":{"action": "read","file_id": "file1","access_level": "admin","attributes": ["owner", "size"]}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"PERMIT","output":{"has_access_to_file":[{"owner":"user1","size":"10MB"}]},"policyName":"docs","statusMessage":"OPA Allowed"}`

## DENY for policy:docs

`curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"docs", "policyFilter": ["has_access_to_file"], "input":{"action": "view","file_id": "file1","access_level": "employee","attributes": ["owner", "size"]}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision

{"decision":"DENY","output":{"has_access_to_file":[]},"policyName":"docs","statusMessage":"OPA Denied"}`


## HealthCheck API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/healthcheck

{"code":200,"healthy":true,"message":"alive","name":"opa-9f0248ea-807e-45f6-8e0f-935e570b75cc","url":"self"}

## Statistics API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/statistics

{"code":200,"denyDecisionsCount":10,"deployFailureCount":0,"deploySuccessCount":0,"indeterminantDecisionsCount":0,"permitDecisionsCount":18,"totalErrorCount":4,"totalPoliciesCount":0,"totalPolicyTypesCount":1,"undeployFailureCount":0,"undeploySuccessCount":0}
