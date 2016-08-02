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


-- These lines require MariaDB 10.1
CREATE USER IF NOT EXISTS 'policy'@'localhost';
CREATE USER IF NOT EXISTS 'sa'@'localhost';
CREATE USER IF NOT EXISTS 'ocsp_resp'@'localhost';
CREATE USER IF NOT EXISTS 'revoker'@'localhost';
CREATE USER IF NOT EXISTS 'importer'@'localhost';
CREATE USER IF NOT EXISTS 'mailer'@'localhost';
CREATE USER IF NOT EXISTS 'cert_checker'@'localhost';
CREATE USER IF NOT EXISTS 'ocsp_update'@'localhost';
CREATE USER IF NOT EXISTS 'test_setup'@'localhost';
CREATE USER IF NOT EXISTS 'purger'@'localhost';

-- Storage Authority
GRANT SELECT,INSERT,UPDATE ON authz TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON pendingAuthorizations TO 'sa'@'localhost';
GRANT SELECT(id,Lockcol) ON pendingAuthorizations TO 'sa'@'localhost';
GRANT SELECT,INSERT ON certificates TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'localhost';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'localhost';
GRANT SELECT,INSERT ON sctReceipts TO 'sa'@'localhost';
GRANT INSERT ON ocspResponses TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON challenges TO 'sa'@'localhost';
GRANT SELECT,INSERT on fqdnSets TO 'sa'@'localhost';

-- OCSP Responder
GRANT SELECT ON certificateStatus TO 'ocsp_resp'@'localhost';
GRANT SELECT ON ocspResponses TO 'ocsp_resp'@'localhost';

-- OCSP Generator Tool (Updater)
GRANT INSERT ON ocspResponses TO 'ocsp_update'@'localhost';
GRANT SELECT ON certificates TO 'ocsp_update'@'localhost';
GRANT SELECT,UPDATE ON certificateStatus TO 'ocsp_update'@'localhost';
GRANT SELECT ON sctReceipts TO 'ocsp_update'@'localhost';

-- Revoker Tool
GRANT SELECT ON registrations TO 'revoker'@'localhost';
GRANT SELECT ON certificates TO 'revoker'@'localhost';

-- External Cert Importer
GRANT SELECT,INSERT,UPDATE,DELETE ON identifierData TO 'importer'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON externalCerts TO 'importer'@'localhost';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'localhost';
GRANT SELECT ON registrations TO 'mailer'@'localhost';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'localhost';
GRANT SELECT ON fqdnSets TO 'mailer'@'localhost';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'localhost';

-- Expired authorization purger
GRANT SELECT,DELETE ON pendingAuthorizations TO 'purger'@'localhost';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'localhost';
