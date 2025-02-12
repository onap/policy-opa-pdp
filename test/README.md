# Testing OPA

## Curl URL For Deployment.

1. `curl -u 'policyadmin:zb!XztG34' -X POST -H "Content-Type":"application/yaml" --data-binary @test_resources/policy_deploy_single_policy.yaml http://localhost:30002/policy/api/v1/policytypes/onap.policies.native.opa/versions/1.0.0/policies`

2. `curl -u 'policyadmin:zb!XztG34' -X POST  -H "Content-Type":"application/json" -d  @test_resources/deploy.json http://localhost:30003/policy/pap/v1/pdps/policies`

## Curl URL For Undeployment

`curl -u 'policyadmin:zb!XztG34' -X DELETE http://localhost:30003/policy/pap/v1/pdps/policies/role/versions/1.0.0` , where role is the policy name.

## Curl URL for Batch Undeployment.

`curl -v -u 'policyadmin:zb!XztG34' -X POST  -H "Content-Type":"application/json" -d  @test_resources/undeploy_batch_delete.json  http://localhost:30003/policy/pap/v1/pdps/deployments/batch`

## Verification API Calls

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyFilter" : [""], "policyName":"example","input":{"method":"POST","path":["users"]}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"allow":true},"policyName":"example"}

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyName":"role", "policyFilter": ["role_grants"], "input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"role_grants":{"billing":[{"action":"read","type":"finance"},{"action":"update","type":"finance"}],"customer":[{"action":"read","type":"dog"},{"action":"read","type":"cat"},{"action":"adopt","type":"dog"},{"action":"adopt","type":"cat"}],"employee":[{"action":"read","type":"dog"},{"action":"read","type":"cat"},{"action":"update","type":"dog"},{"action":"update","type":"cat"}]}},"policyName":"role"}

## OUTPUT for policy:action with filter role_permissions

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": ["role_permissions"]__, "policyName":"action","input":{"user":"alice","action":"delete","type":"server"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"role_permissions":{"admin":{"actions":["read","write","delete"],"resources":["server","database"]},"editor":{"actions":["read","write"],"resources":["server"]},"viewer":{"actions":["read"],"resources":["server"]}}},"policyName":"action"}

## OUTPUT for policy:action with empty filters

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": [""]__, "policyName":"action","input":{"user":"alice","action":"delete","type":"server"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"allow":true,"role_permissions":{"admin":{"actions":["read","write","delete"],"resources":["server","database"]},"editor":{"actions":["read","write"],"resources":["server"]},"viewer":{"actions":["read"],"resources":["server"]}},"user_roles":{"alice":["admin"],"bob":["editor"],"charlie":["viewer"]}},"policyName":"action"}

## OUTPUT for policy:action without filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"action","input":{"user":"charlie","action":"delete","type":"server"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"errorMessage":"Policy Filter is nil.","policyName":"","responseCode":"bad_request"}

## OUTPUT for policy:account with filter account_attributes

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC","timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": ["account_attributes"]__, "policyName":"account", "input":{"creditor_account":11111,"creditor":"alice","debtor_account":22222,"debtor":"bob","period":30,"amount":1000}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"account_attributes":{"11111":{"amount":10000,"owner":"alice"},"22222":{"amount":10000,"owner":"bob"},"33333":{"amount":10000,"owner":"cam"}}},"policyName":"account"}

## OUTPUT for policy:account with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC","timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": [""]__, "policyName":"account", "input":{"creditor_account":11111,"creditor":"alice","debtor_account":22222,"debtor":"bob","period":30,"amount":1000}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"account_attributes":{"11111":{"amount":10000,"owner":"alice"},"22222":{"amount":10000,"owner":"bob"},"33333":{"amount":10000,"owner":"cam"}},"allow":true,"amount_is_valid":true,"creditor_is_valid":true,"debtor_is_valid":true,"period_is_valid":true},"policyName":"account"}

## OUTPUT for policy:organization with filter acls

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": ["acls"]__, "policyName":"organization", "input":{"user":"alice","action": "read","component": "component_A","project": "project_A", "organization": "org_A"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"acls":[{"actions":["edit","read"],"component":"component_A","organization":"org_A","project":"project_A","user":"alice"},{"actions":["read"],"organization":"org_A","user":"bob"},{"action":["edit"],"component":"component_A","organization":"org_A","project":"project_B","user":"bob"},{"action":["read"],"organization":"org_A","project":"project_B","user":"charlie"}]},"policyName":"organization"}

## OUTPUT for policy:organization with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "11:34:56", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z",__"policyFilter": [""]__, "policyName":"organization", "input":{"user":"alice","action": "read","component": "component_A","project": "project_A", "organization": "org_A"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"acls":[{"actions":["edit","read"],"component":"component_A","organization":"org_A","project":"project_A","user":"alice"},{"actions":["read"],"organization":"org_A","user":"bob"},{"action":["edit"],"component":"component_A","organization":"org_A","project":"project_B","user":"bob"},{"action":["read"],"organization":"org_A","project":"project_B","user":"charlie"}],"allow":true},"policyName":"organization"}

## OUTPUT for policy:abac with filter viewable_sensor_data

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"abac", __"policyFilter": ["viewable_sensor_data"]__, "input":{"actions": ["write"],"datatypes": ["location","temperature","precipitation","windspeed"],"time_period": {"from": "2024-03-27","to": "2024-03-31"}}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"viewable_sensor_data":[]},"policyName":"abac"}

## OUTPUT for policy:abac with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"abac", __"policyFilter": [""]__, "input":{"actions": ["write"],"datatypes": ["location","temperature","precipitation","windspeed"],"time_period": {"from": "2024-03-27","to": "2024-03-31"}}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"allow":false,"sensor_data":[{"humidity":"40%","id":"0001","location":"Sri Lanka","particle_density":"1.3 g/l","precipitation":"1000 mm","temperature":"28 C","timestamp":"2024-02-26","windspeed":"5.5 m/s"},{"humidity":"45%","id":"0002","location":"Colombo","particle_density":"1.5 g/l","precipitation":"1200 mm","temperature":"30 C","timestamp":"2024-02-26","windspeed":"6.0 m/s"},{"humidity":"60%","id":"0003","location":"Kandy","particle_density":"1.1 g/l","precipitation":"800 mm","temperature":"25 C","timestamp":"2024-02-26","windspeed":"4.5 m/s"},{"humidity":"30%","id":"0004","location":"Galle","particle_density":"1.8 g/l","precipitation":"500 mm","temperature":"35 C","timestamp":"2024-02-27","windspeed":"7.2 m/s"},{"humidity":"20%","id":"0005","location":"Jaffna","particle_density":"0.9 g/l","precipitation":"300 mm","temperature":"-5 C","timestamp":"2024-02-27","windspeed":"3.8 m/s"},{"humidity":"55%","id":"0006","location":"Trincomalee","particle_density":"1.2 g/l","precipitation":"1000 mm","temperature":"20 C","timestamp":"2024-02-28","windspeed":"5.0 m/s"},{"humidity":"50%","id":"0007","location":"Nuwara Eliya","particle_density":"1.3 g/l","precipitation":"600 mm","temperature":"25 C","timestamp":"2024-02-28","windspeed":"4.0 m/s"},{"humidity":"40%","id":"0008","location":"Anuradhapura","particle_density":"1.4 g/l","precipitation":"700 mm","temperature":"28 C","timestamp":"2024-02-29","windspeed":"5.8 m/s"},{"humidity":"65%","id":"0009","location":"Matara","particle_density":"1.6 g/l","precipitation":"900 mm","temperature":"32 C","timestamp":"2024-02-29","windspeed":"6.5 m/s"}],"viewable_sensor_data":[]},"policyName":"abac"}

## OUTPUT for policy:zone with filter has_zone_access

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"zone", __"policyFilter": ["has_zone_access"]__, "input":{"actions": ["view"],"log_id": "log1", "datatypes": ["access", "user"],"time_period": {"from": "2024-11-01T09:00:00Z","to": "2024-11-01T10:00:00Z"},"zone_id": "zoneA"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"has_zone_access":[{"access":"granted","user":"user1"}]},"policyName":"zone"}

## OUTPUT for policy:zone with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"zone", __"policyFilter": [""]__, "input":{"actions": ["view"],"log_id": "log1", "datatypes": ["access", "user"],"time_period": {"from": "2024-11-01T09:00:00Z","to": "2024-11-01T10:00:00Z"},"zone_id": "zoneA"}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"action_is_log_view":true,"allow":true,"has_zone_access":[{"access":"granted","user":"user1"}],"zone":{"zone_access_logs":[{"access":"granted","log_id":"log1","timestamp":"2024-11-01T09:00:00Z","user":"user1","zone_id":"zoneA"},{"access":"denied","log_id":"log2","timestamp":"2024-11-01T10:30:00Z","user":"user2","zone_id":"zoneA"},{"access":"granted","log_id":"log3","timestamp":"2024-11-01T11:00:00Z","user":"user3","zone_id":"zoneB"}]}},"policyName":"zone"}

## OUTPUT for policy:vehicle with filter user_has_vehicle_access

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"vehicle", __"policyFilter": ["user_has_vehicle_access"]__, "input":{"actions": ["use"],"user":"user1", "vehicle_id": "v1", "attributes": ["type", "status"]}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"user_has_vehicle_access":[{"status":"available","type":"car"}]},"policyName":"vehicle"}

## OUTPUT for policy:vehicle with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"vehicle", __"policyFilter": [""]__, "input":{"actions": ["use"],"user":"user1", "vehicle_id": "v1", "attributes": ["type", "status"]}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"action_is_granted":true,"allow":true,"user_has_vehicle_access":[{"status":"available","type":"car"}],"vehicles":[{"owner":"user1","status":"available","type":"car","vehicle_id":"v1"},{"owner":"user2","status":"in use","type":"bike","vehicle_id":"v2"}]},"policyName":"vehicle"}

## OUTPUT for policy:docs with filter has_access_to_file

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"docs", __"policyFilter": ["has_access_to_file"]__, "input":{"action": "read","file_id": "file1","access_level": "admin","attributes": ["owner", "size"]}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"has_access_to_file":[{"owner":"user1","size":"10MB"}]},"policyName":"docs"}

## OUTPUT for policy:docs with empty filter

curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22","policyName":"docs", __"policyFilter": [""]__, "input":{"action": "read","file_id": "file1","access_level": "admin","attributes": ["owner", "size"]}}' -X POST http://0.0.0.0:8282/policy/pdpo/v1/decision

{"output":{"action_is_read_or_write":true,"allow":true,"files":[{"access_level":"admin","file_id":"file1","owner":"user1","size":"10MB"},{"access_level":"user","file_id":"file2","owner":"user2","size":"5MB"}],"has_access_to_file":[{"owner":"user1","size":"10MB"}]},"policyName":"docs"}



## HealthCheck API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpo/v1/healthcheck

{"code":200,"healthy":true,"message":"alive","name":"opa-ea84b1ff-00de-4bf6-a039-222e4511d0a1","url":"self"}

## Statistics API Call With Response

curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpo/v1/statistics

{"code":200,"decisionFailureCount":0,"decisionSuccessCount":9,"deployFailureCount":0,"deploySuccessCount":0,"totalErrorCount":5,"totalPoliciesCount":0,"totalPolicyTypesCount":1,"undeployFailureCount":0,"undeploySuccessCount":0}
