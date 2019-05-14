#!/bin/bash

DOCKERFILE=$1

args=("$@")

DOCKERCOMPOSEARGS=""

for (( i = 0; i < $#; i++ )); do
	if [ $i -ne 0 ]; then
		DOCKERCOMPOSEARGS="$DOCKERCOMPOSEARGS ${args[$i]}"
	fi
done

# echo $DOCKERCOMPOSEARGS

if [[ $1 == "default" ]]; then
	docker-compose up$DOCKERCOMPOSEARGS
elif [[ $1 == "test" ]]; then
	docker-compose -f docker-compose.test.yml up$DOCKERCOMPOSEARGS
elif [[ $1 == "nginx" ]]; then
	docker-compose -f docker-compose.nginx.yml up$DOCKERCOMPOSEARGS
else
	docker-compose -f docker-compose.yml -f docker-compose.$1.yml up$DOCKERCOMPOSEARGS
fi