# Running docker  policy-opa-pdp

## Building Docker Image.
docker build -t opa-pdp:1.0.0 .


## Generating models with openapi.yaml

1. oapi-codegen -package=oapicodegen  -generate "models" openapi.yaml > models.go


## Creating New Policy

1. Create a tosca policy file that has policy.rego and data.json encoded contents.

2. Ensure data key should have node as prefix. For example refer to test/test_resources/blacklist/policy_blacklist.yaml.

3. OPA emphasizes that each policy should have a unique policy-name/policy-id,

   example:
   Not Allowed: 
   1. If a policy named onap.org.cell is deployed, then deploying a policy named onap.org.cell.consistency is disallowed because it shares the same hierarchical structure.

   2. If a policy named onap.org.cell is deployed, then deploying a policy named onap.org is disallowed because it is parent directory.

   Allowed: If a policy named onap.org.cell is deployed, then deploying a policy named onap.org.consistency is permitted, as it does not share the same hierarchy.


4. Policy key should start (prefixed) with policy-id. For ex refer to test/test_resources/blacklist/policy_blacklist.yaml.

5. Create a deploy.json file to deploy through pap. Refer to file under test/test_resources/blacklist/deploy_blacklist.json.

## Deploy Policy Using Docker Compose

1. Ensure you have docker and docker-compose installed

2. Check out the policy/docker repo from the ONAP gerrit or from github: https://github.com/onap/policy-docker

3. Latest Docker image created can be updated in compose.yml inside policy/docker repo.

4. Start opa-pdp containers by running the start-compose.sh script

5. Command to start opa-pdp container ./start-compose.sh opa-pdp

6. Check the logs. docker logs -f policy-opa-pdp


## Testing Decision Api

To get opa Decision for the deployed policies please refer to  test/README.md for the API details.
