# Running docker  policy-opa-pdp

## Building Docker Image.
docker build -f  ./build/Dockerfile  -t opa-pdp:1.1.1 .

## Running the containers and Testing

1. docker image ls | grep opa-pdp

2. inside test directory run - docker-compose down
   
3.  docker-compose up -d

4.  docker logs -f opa-pdp




