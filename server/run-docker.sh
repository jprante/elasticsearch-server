#!/bin/sh

docker run -d -p 9200:9200 -p 9300:9300 --name elasticsearch jprante/elasticsearch:6.3.2.0
