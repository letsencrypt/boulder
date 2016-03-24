#
# Copyright 2015 ISRG.  All rights reserved
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Before setting up any privileges, we revoke existing ones to make sure we
# start from a clean slate.

print_drop_user policy
print_drop_user sa
print_drop_user ocsp_resp
print_drop_user ocsp_update
print_drop_user revoker
print_drop_user importer
print_drop_user mailer
print_drop_user cert_checker
print_drop_user backfiller
