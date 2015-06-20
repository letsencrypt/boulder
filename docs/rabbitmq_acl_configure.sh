#!/bin/bash
# Copyright 2015 ISRG.  All rights reserved
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This file creates individual AMQP accounts for each Boulder component,
# and sets restrictive access controls on those accounts.
#
# You can use this tool without any configuration to produce users named
# [am, ca, sa, ra, va, wfe, ocsp-updater] which all have the password "guest".
# You can also customize this tool by creating a config file that will be
# sourced. By default this file is obtained from $HOME/.rabbitmq_config, but
# you can override the config file path using the environment variable
# RABBITMQ_ACL_CONFIG, such as:
#
# $ RABBITMQ_ACL_CONFIG=myconfig ./rabbitmq_acl_configure.sh

# VARIABLES
PORT=15672
HOST=localhost
VHOST="/"
EXTRA=""
RABBIT_ADMIN=$(which rabbitmqadmin)

# USER NAMES
USER_BOULDER_AM="am"
USER_BOULDER_CA="ca"
USER_BOULDER_SA="sa"
USER_BOULDER_RA="ra"
USER_BOULDER_VA="va"
USER_BOULDER_WFE="wfe"
USER_BOULDER_OCSP="ocsp-updater"

# PASSWORDS
PASS_BOULDER_AM="guest"
PASS_BOULDER_CA="guest"
PASS_BOULDER_SA="guest"
PASS_BOULDER_RA="guest"
PASS_BOULDER_VA="guest"
PASS_BOULDER_WFE="guest"
PASS_BOULDER_OCSP="guest"

# To use different options, you should create an override
# file with whatever changes you want for the above variables
RABBITMQ_ACL_CONFIG=${RABBITMQ_ACL_CONFIG:-$HOME/.rabbitmq_config}

if [ -r "${RABBITMQ_ACL_CONFIG}" ] ; then
  echo "Loading overrides from ${RABBITMQ_ACL_CONFIG}..."
  source "${RABBITMQ_ACL_CONFIG}"
fi

if ! [ -x "${RABBIT_ADMIN}" ] ; then
  echo "Could not locate rabbitmqadmin; please set RABBIT_ADMIN in your ${RABBITMQ_ACL_CONFIG} file."
  exit 1
fi

run() {
  echo $*
  $*
}

admin() {
  run ${RABBIT_ADMIN} -H ${HOST} -P ${PORT} -V ${VHOST} ${EXTRA} $*
}

admin declare queue name="Monitor" durable=false
admin declare queue name="CA.server" durable=false
admin declare queue name="SA.server" durable=false
admin declare queue name="RA.server" durable=false
admin declare queue name="VA.server" durable=false

admin declare exchange name="boulder" type=topic durable=false
admin declare binding source="boulder" destination="Monitor" routing_key="#"

admin declare user name=${USER_BOULDER_AM} password=${PASS_BOULDER_AM} tags=""
admin declare user name=${USER_BOULDER_CA} password=${PASS_BOULDER_CA} tags=""
admin declare user name=${USER_BOULDER_SA} password=${PASS_BOULDER_SA} tags=""
admin declare user name=${USER_BOULDER_RA} password=${PASS_BOULDER_RA} tags=""
admin declare user name=${USER_BOULDER_VA} password=${PASS_BOULDER_VA} tags=""
admin declare user name=${USER_BOULDER_WFE} password=${PASS_BOULDER_WFE} tags=""
admin declare user name=${USER_BOULDER_OCSP} password=${PASS_BOULDER_OCSP} tags=""

admin declare permission vhost=${VHOST} user=${USER_BOULDER_AM} configure="^$" write="^$" read="^Monitor$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_VA} configure="^(VA\.server|VA->.*)$" write="^(boulder|VA\.server|VA->.*)$" read="^(boulder|VA\.server|VA->.*)$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_RA} configure="^(RA\.server|RA->.*)$" write="^(boulder|RA\.server|RA->.*)$" read="^(boulder|RA\.server|RA->.*)$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_CA} configure="^(CA\.server|CA->.*)$" write="^(boulder|CA\.server|CA->.*)$" read="^(boulder|CA\.server|CA->.*)$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_SA} configure="^(SA\.server|SA->.*)$" write="^(boulder|SA\.server|SA->.*)$" read="^(boulder|SA\.server|SA->.*)$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_WFE} configure="^(WFE->.*)$" write="^(boulder|WFE->.*)$" read="^(boulder|WFE->.*)$"
admin declare permission vhost=${VHOST} user=${USER_BOULDER_OCSP} configure="^(OCSP->.*)$" write="^(boulder|OCSP->.*)$" read="^(boulder|OCSP->.*)$"
