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

# helper function to get boot2docker ip if we are on a mac
hostip=0.0.0.0
if command -v boot2docker >/dev/null 2>&1 ; then
	hostip="$(boot2docker ip)"
fi
# if the DOCKER_HOST variable exists, lets get the host ip from that
if [[ ! -z "$DOCKER_HOST" ]]; then
	hostip="$(echo $DOCKER_HOST | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
fi

# In order to talk to a letsencrypt client running on the host, the fake DNS
# client used in Boulder's start.py needs to know what the host's IP is from the
# perspective of the container. We try to figure it out automatically. If you'd
# like your Boulder instance to always talk to some other host, you can set
# FAKE_DNS to that host's IP address.
if [ -z "${FAKE_DNS}" ] ; then
  FAKE_DNS=$(/sbin/ifconfig docker0 | sed -n 's/ *inet addr:\([0-9.]\+\).*/\1/p')
fi

if [[ "$(is_running boulder-mysql)" != "true" ]]; then
	# bring up mysql mariadb container
	docker run -d \
		--net host \
		-p 3306:3306 \
		-e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
		--name boulder-mysql \
		mariadb:10.0
fi

if [[ "$(is_running boulder-rabbitmq)" != "true" ]]; then
	# bring up rabbitmq container
	docker run -d \
		--net host \
		-p 5672:5672 \
		--name boulder-rabbitmq \
		rabbitmq:3
fi

# build the boulder docker image
docker build --rm --force-rm -t letsencrypt/boulder .

# run the boulder container
# The excluding `-d` command makes the instance interactive, so you can kill
# the boulder container with Ctrl-C.
docker run --rm -it \
	--net host \
	-p 4000:4000 \
	-e MYSQL_CONTAINER=yes \
	--name boulder \
	letsencrypt/boulder
