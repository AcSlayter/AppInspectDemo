#!/bin/bash

echo "docker build"
docker build -f DockerFile -t splunk-app-inspect .

docker run -t splunk-app-inspect