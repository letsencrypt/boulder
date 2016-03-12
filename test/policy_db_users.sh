#
# Copyright 2015 ISRG.  All rights reserved
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This file defines the default users for the primary database, used by
# all the parts of Boulder except the Certificate Authority module, which
# utilizes its own database.
#

# Policy loader, CA, RA
# Note: The same config section, "pa" is used by the policy loader (for writes)
# and the CA and RA (for reads). So right now we have the one user that has
# both read and write permission, even though it would be better to give only
# read permission to CA and RA.
print_grant SELECT,INSERT,DELETE blacklist policy
print_grant SELECT,INSERT,DELETE whitelist policy

# Test setup and teardown
print_grant 'ALL PRIVILEGES' '*' test_setup

