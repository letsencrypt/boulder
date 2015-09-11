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

# In order to talk to a letsencrypt client running on the host, the fake DNS
# client used in Boulder's start.py needs to know what the host's IP is from the
# perspective of the container. We try to figure it out automatically. If you'd
# like your Boulder instance to always talk to some other host, you can set
# FAKE_DNS to that host's IP address.
if [ -z "${FAKE_DNS}" ] ; then
  FAKE_DNS=$(ifconfig docker0 | sed -n 's/ *inet addr:\([0-9.]\+\).*/\1/p')
fi
docker build --tag boulder .
# The -i command makes the instance interactive, so you can kill start.py with Ctrl-C.
docker run \
  --interactive \
  --tty \
  --rm=true \
  --publish 4000-4001:4000-4001 \
  --publish 8000-8100:8000-8100 \
  --env FAKE_DNS="${FAKE_DNS}" \
  boulder
