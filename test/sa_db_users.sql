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

-- Storage Authority
GRANT SELECT,INSERT,UPDATE ON authz TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE,DELETE ON pendingAuthorizations TO 'sa'@'127.0.0.1';
GRANT SELECT(id,Lockcol) ON pendingAuthorizations TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT ON certificates TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT ON sctReceipts TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT ON deniedCSRs TO 'sa'@'127.0.0.1';
GRANT INSERT ON ocspResponses TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE ON challenges TO 'sa'@'127.0.0.1';

-- OCSP Responder
GRANT SELECT ON certificateStatus TO 'ocsp_resp'@'127.0.0.1';
GRANT SELECT ON ocspResponses TO 'ocsp_resp'@'127.0.0.1';

-- OCSP Generator Tool (Updater)
GRANT INSERT ON ocspResponses TO 'ocsp_update'@'127.0.0.1';
GRANT SELECT ON certificates TO 'ocsp_update'@'127.0.0.1';
GRANT SELECT,UPDATE ON certificateStatus TO 'ocsp_update'@'127.0.0.1';
GRANT SELECT ON sctReceipts TO 'ocsp_update'@'127.0.0.1';

-- Revoker Tool
GRANT SELECT ON registrations TO 'revoker'@'127.0.0.1';
GRANT SELECT ON certificates TO 'revoker'@'127.0.0.1';
GRANT SELECT,INSERT ON deniedCSRs TO 'revoker'@'127.0.0.1';

-- External Cert Importer
GRANT SELECT,INSERT,UPDATE,DELETE ON identifierData TO 'importer'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE,DELETE ON externalCerts TO 'importer'@'127.0.0.1';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'127.0.0.1';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'127.0.0.1';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'127.0.0.1';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'127.0.0.1';
