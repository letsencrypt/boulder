--
-- Copyright 2015 ISRG.  All rights reserved
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
--
-- This file defines the default users for the primary database, used by
-- all the parts of Boulder except the Certificate Authority module, which
-- utilizes its own database.
--

-- Create users for each component with the appropriate permissions. We want to
-- drop each user and recreate them, but if the user doesn't already exist, the
-- drop command will fail. So we grant the dummy `USAGE` privilege to make sure
-- the user exists and then drop the user.

-- Policy loader, CA, RA
-- Note: The same config section, "pa" is used by the policy loader (for writes)
-- and the CA and RA (for reads). So right now we have the one user that has
-- both read and write permission, even though it would be better to give only
-- read permission to CA and RA.
GRANT SELECT,INSERT,DELETE ON blacklist TO 'policy'@'localhost';
GRANT SELECT,INSERT,DELETE ON whitelist TO 'policy'@'localhost';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'localhost';
