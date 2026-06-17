#!/bin/bash

docker build --tag=finale .
docker run -it -p 9001:9001 --rm --name=finale finale