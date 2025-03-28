# Testing OPA

## Curl URL For Deployment.

1. `curl -u 'policyadmin:zb!XztG34' -X POST -H "Content-Type":"application/yaml" --data-binary @toscapolicies/role/policy_role.yaml http://localhost:30002/policy/api/v1/policytypes/onap.policies.native.opa/versions/1.0.0/policies`

2. `curl -u 'policyadmin:zb!XztG34' -X POST  -H "Content-Type":"application/json" -d  @toscapolicies/role/deploy_role.json http://localhost:30003/policy/pap/v1/pdps/policies`

## Curl URL For Undeployment

`curl -u 'policyadmin:zb!XztG34' -X DELETE http://localhost:30003/policy/pap/v1/pdps/policies/role/versions/1.0.0` , where role is the policy name.

## Curl URL for Batch Undeployment.

`curl -v -u 'policyadmin:zb!XztG34' -X POST  -H "Content-Type":"application/json" -d  @{"groups": [{"name": "opaGroup","deploymentSubgroups": [{"pdpType": "opa","action": "DELETE","policies": [{"name": "role","version": "2.0.2"}]}]}]}  http://localhost:30003/policy/pap/v1/pdps/deployments/batch`

## Decision API Response 

## Output For Policy: access_method with empty filter
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : [""], "policyName":"access_method","input":{"method":"POST","path":["users"]}}' -X POST http://0.0.0.0:30012/policy/pdpo/v1/decision

{"output":{"allow":true},"policyName":"access_method"}

## Output For Policy: access_method with filter allow
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : ["allow"], "policyName":"access_method","input":{"method":"POST","path":["users"]}}' -X POST http://0.0.0.0:30012/policy/pdpo/v1/decision

{"output":{"allow":true},"policyName":"access_method"}

## Output For Policy: role with filter allow

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyName":"role", "policyFilter": ["allow"], "input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:30012/policy/pdpo/v1/decision

{"output":{"allow":true},"policyName":"role"}


## Output For policy: role with empty filter
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyName":"role", "policyFilter": [""], "input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:30012/policy/pdpo/v1/decision

{"output":{"allow":true,"user_is_admin":true,"user_is_granted":[]},"policyName":"role"}

## Output For policy: role with filter not matching the allowable filters
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyName":"role", "policyFilter": ["abc"], "input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:30012/policy/pdpo/v1/decision

{"output":null,"policyName":"role","statusMessage":"Policy Filter(s) not matching, Valid Filter(s) are: [allow, user_is_admin, user_is_granted]"}

## Output For Policy: blacklist with filter module_allow
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : ["module_allow"], "policyName":"blacklist","input":{"vfmodule":["the-vfmodule-where-root-is-true","another-vfmodule-where-root-is-true" ] }}' -X POST http://localhost:30012/policy/pdpo/v1/decision

{"output":{"module_allow":{"another-vfmodule-where-root-is-true":true,"the-vfmodule-where-root-is-true":true}},"policyName":"blacklist"}

## Output For Policy: blacklist with Empty Filter
 curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : [""], "policyName":"blacklist","input":{"vfmodule":["the-vfmodule-where-root-is-true","another-vfmodule-where-root-is-true" ] }}' -X POST http://localhost:30012/policy/pdpo/v1/decision

{"output":{"module_allow":{"another-vfmodule-where-root-is-true":true,"the-vfmodule-where-root-is-true":true}},"policyName":"blacklist"}

## Output For Policy: monitor with filter result
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : ["result"], "policyName":"monitor","input":{ "domain": "measurementsForVfScaling", "eventName": "Measurement_vGMUX","controlLoopSchemaType": "VNF","policyScope": "DCAE","policyName": "DCAE.Config_tca-hi-lo","policyVersion": "v0.0.1", "version": "1.0.2","controlname": "ControlLoop-vCPE-48f0c2c3-a172-4192-9ae3-052274181b6e","thresholdValue": 0}}' -X POST http://localhost:30012/policy/pdpo/v1/decision

{"output":{"result":[{"closedLoopEventStatus":"ABATED","severity":"MAJOR"}]},"policyName":"monitor"}

## Output For Policy: monitor with empty filter
curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "08:26:41.857Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2025-01-17T08:26:41.857Z", "policyFilter" : [""], "policyName":"monitor","input":{ "domain": "measurementsForVfScaling", "eventName": "Measurement_vGMUX","controlLoopSchemaType": "VNF","policyScope": "DCAE","policyName": "DCAE.Config_tca-hi-lo","policyVersion": "v0.0.1", "version": "1.0.2","controlname": "ControlLoop-vCPE-48f0c2c3-a172-4192-9ae3-052274181b6e","thresholdValue": 0}}' -X POST http://localhost:30012/policy/pdpo/v1/decision

{"output":{"result":[{"closedLoopEventStatus":"ABATED","severity":"MAJOR"}]},"policyName":"monitor


## HealthCheck API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:30012/policy/pdpo/v1/healthcheck

{"code":200,"healthy":true,"message":"alive","name":"opa-ea84b1ff-00de-4bf6-a039-222e4511d0a1","url":"self"}

## Statistics API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:30012/policy/pdpo/v1/statistics

{"code":200,"decisionFailureCount":0,"decisionSuccessCount":0,"deployFailureCount":0,"deploySuccessCount":0, "totalErrorCount":0,"totalPoliciesCount":0,"totalPolicyTypesCount":1,"undeployFailureCount":0,"undeploySuccessCount":0}

