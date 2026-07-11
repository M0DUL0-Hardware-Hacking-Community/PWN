#!/bin/sh
docker build --tag=khp_protocol .
docker run -it -p 1337:1337 --rm --name=khp_protocol khp_protocol
