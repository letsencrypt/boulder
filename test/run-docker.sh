#!/bin/bash
#
# Build and run a docker image for Boulder. This is suitable for running
# repeatedly during development because Docker will cache the image it builds,
# and will only re-do the minimum necessary.
#
# NOTE: Currently we're not able to effectively cache the DB setup steps,
# because setting up the DB depends on source files in the Boulder repo. So any
# time source files change, Docker treats that as potentially invalidating the
# steps that came after the COPY. In theory we could add a step that copies only
# the files necessary to do the migrations, run them, and then copy the rest of
# the source.
set -o errexit
cd $(dirname $0)/..

# helper function to return the state of the container (true if running, false if not)
is_running(){
	local name=$1
	local state=$(docker inspect --format "{{.State.Running}}" $name 2>/dev/null)

	if [[ "$state" == "false" ]]; then
		# the container is up but not running
		# we should remove it so we can bring up another
		docker rm $name
	fi
	echo $state
}

# To share the same boulder config between docker and non-docker cases
# we use host networking but restrict containers to listen to
# 127.0.0.1 to avoid exposing services beyond the host.

if [[ "$(is_running boulder-mysql)" != "true" ]]; then
	# bring up mysql mariadb container - no need to publish port
	# 3306 with host networking
	docker run -d \
		-e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
		--name boulder-mysql \
		mariadb:10.1 mysqld --bind-address=0.0.0.0
fi

if [[ "$(is_running boulder-rabbitmq)" != "true" ]]; then
	docker run -d \
		-e RABBITMQ_NODE_IP_ADDRESS=0.0.0.0 \
		--name boulder-rabbitmq \
		rabbitmq:3
fi

# build the boulder docker image
docker build --rm --force-rm -t letsencrypt/boulder .

# In order to talk to a letsencrypt client running on the host, the fake DNS
# client used in Boulder's start.py needs to know what the host's IP is from the
# perspective of the container. The default value is 127.0.0.1. If you'd
# like your Boulder instance to always talk to some other host, you can set
# FAKE_DNS to that host's IP address.
fake_dns_args=()
if [[ $FAKE_DNS ]]; then
    fake_dns_args=(-e "FAKE_DNS=$FAKE_DNS")
fi

# run the boulder container
# The excluding `-d` command makes the instance interactive, so you can kill
# the boulder container with Ctrl-C.
docker run --rm -it \
	"${fake_dns_args[@]}" \
	-p 4000:4000 \
	-p 4002:4002 \
	-p 4003:4003 \
	-p 4430:4430 \
	-p 8053:8053 \
	-p 8055:8055 \
		--name boulder \
		--link=boulder-mysql:boulder-mysql \
		--link=boulder-rabbitmq:boulder-rabbitmq \
		--add-host=boulder:127.0.0.1 \
	letsencrypt/boulder "$@"
