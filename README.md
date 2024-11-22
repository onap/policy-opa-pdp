# Running docker  policy-opa-pdp

## Building Docker Image.
docker build -f  ./build/Dockerfile  -t opa-pdp:1.0.0 .

## Running the containers and Testing

1. docker image ls | grep opa-pdp

2. inside test directory run - docker-compose down
   
3.  docker-compose up -d

4.  docker logs -f opa-pdp

## Generating models with openapi.yaml
   
1. oapi-codegen -package=oapicodegen  -generate "models" openapi.yaml > models.go

## Creating new Policy

1. Create a new directory under test/polices. For example - role

2. Inside this directory create a policy [i.e; rego file] named policy.rego. Version 1 i.e v1 is supported  for rego files.

3. For contents you can see example of  policy.rego under test/policies/role/policy.rego. 

3. Inside test/policies/data create a new directory with the package name of policy.rego. For example test/policies/data/role

4. Create a file data.json under the newly created directory inside data. For example test/policies/data/data.json

5. In policy.rego the package declaration organizes the policy rules. This allows 

6. The Rule allow evaluates to true/false based on the logic defined in policy.rego

7. Data.json is files is kept within the directory named after policy package name under data folders. For example policies/data/role/data.json.

8. To reference the data inside policy.rego we need to define rule as data.folder-name.attribute. For example you can refer to policy.rego under rules, data.role.user_roles.

9. To deploy a new policy opa-pdp need to be redpolyed i.e; docker-compose down and up need to be executed.

## Testing Decision Api

send json 
{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC",  "timeOffset": "+05:30", "currentDateTime": "2024-11-22 12:08:00.123456+0000 ", "policyName":"role/allow","input":{"user":"alice","action":"write","object":"id123","type":"dog"}} 
to opa-pdp as shown in curl commands below.

"policyName":"[packagename in rego file]/allow"
  Policy to be refrenced as policyName:role/allow in case when policy's package name is role. Change it according to  your package name of the policy.

"input":{"user":"alice","action":"read","object":"id123","type":"dog"}
  Input defines the specific data to be evaluated by the Rego policy

## Verification API Calls

`curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyName":"role/allow","input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision`

## Result Of Verification API calls(Success)

`curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC",  "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyName":"role/allow","input":{"user":"alice","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision`

`{"decision":"PERMIT","policyName":"role/allow","statusMessage":"OPA Allowed"}`


## Result of Verification API calls(Failure)

`curl -u 'policyadmin:zb!XztG34' -H 'Content-Type: application/json' -H 'Accept: application/json' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -d '{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS","currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC",  "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z", "policyName":"role/allow","input":{"user":"carol","action":"write","object":"id123","type":"dog"}}' -X POST http://0.0.0.0:8282/policy/pdpx/v1/decision`

## HealthCheck API Call With Response

`curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/healthcheck`

`{"code":200,"healthy":true,"message":"alive","name":"opa-9f0248ea-807e-45f6-8e0f-935e570b75cc","url":"self"}`

## Statistics API Call With Response

`curl -u 'policyadmin:zb!XztG34' --header 'X-ONAP-RequestID:8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1' -X GET http://0.0.0.0:8282/policy/pdpx/v1/statistics`

`{"code":200,"denyDecisionsCount":10,"deployFailureCount":0,"deploySuccessCount":0,"indeterminantDecisionsCount":0,"permitDecisionsCount":18,"totalErrorCount":4,"totalPoliciesCount":0,"totalPolicyTypesCount":1,"undeployFailureCount":0,"undeploySuccessCount":0}`

