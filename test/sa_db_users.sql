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
GRANT SELECT,INSERT,UPDATE ON authz TO 'sa'@'boulder';
GRANT SELECT,INSERT,UPDATE,DELETE ON pendingAuthorizations TO 'sa'@'boulder';
GRANT SELECT(id,Lockcol) ON pendingAuthorizations TO 'sa'@'boulder';
GRANT SELECT,INSERT ON certificates TO 'sa'@'boulder';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'boulder';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'boulder';
GRANT SELECT,INSERT ON sctReceipts TO 'sa'@'boulder';
GRANT SELECT,INSERT ON deniedCSRs TO 'sa'@'boulder';
GRANT INSERT ON ocspResponses TO 'sa'@'boulder';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'boulder';
GRANT SELECT,INSERT,UPDATE ON challenges TO 'sa'@'boulder';
GRANT SELECT,INSERT on fqdnSets TO 'sa'@'boulder';

-- OCSP Responder
GRANT SELECT ON certificateStatus TO 'ocsp_resp'@'boulder';
GRANT SELECT ON ocspResponses TO 'ocsp_resp'@'boulder';

-- OCSP Generator Tool (Updater)
GRANT INSERT ON ocspResponses TO 'ocsp_update'@'boulder';
GRANT SELECT ON certificates TO 'ocsp_update'@'boulder';
GRANT SELECT,UPDATE ON certificateStatus TO 'ocsp_update'@'boulder';
GRANT SELECT ON sctReceipts TO 'ocsp_update'@'boulder';

-- Revoker Tool
GRANT SELECT ON registrations TO 'revoker'@'boulder';
GRANT SELECT ON certificates TO 'revoker'@'boulder';
GRANT SELECT,INSERT ON deniedCSRs TO 'revoker'@'boulder';

-- External Cert Importer
GRANT SELECT,INSERT,UPDATE,DELETE ON identifierData TO 'importer'@'boulder';
GRANT SELECT,INSERT,UPDATE,DELETE ON externalCerts TO 'importer'@'boulder';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'boulder';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'boulder';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'boulder';

-- Name set table backfiller
GRANT SELECT ON certificates to 'backfiller'@'boulder';
GRANT INSERT,SELECT ON fqdnSets to 'backfiller'@'boulder';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'boulder';
