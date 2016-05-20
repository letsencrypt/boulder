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

-- Create users using MariaDB 10.0 syntax

-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.

GRANT USAGE ON *.* TO 'policy'@'localhost';
DROP USER 'policy'@'localhost';
GRANT USAGE ON *.* TO 'sa'@'localhost';
DROP USER 'sa'@'localhost';
GRANT USAGE ON *.* TO 'ocsp_resp'@'localhost';
DROP USER 'ocsp_resp'@'localhost';
GRANT USAGE ON *.* TO 'ocsp_update'@'localhost';
DROP USER 'ocsp_update'@'localhost';
GRANT USAGE ON *.* TO 'revoker'@'localhost';
DROP USER 'revoker'@'localhost';
GRANT USAGE ON *.* TO 'importer'@'localhost';
DROP USER 'importer'@'localhost';
GRANT USAGE ON *.* TO 'mailer'@'localhost';
DROP USER 'mailer'@'localhost';
GRANT USAGE ON *.* TO 'cert_checker'@'localhost';
DROP USER 'cert_checker'@'localhost';
GRANT USAGE ON *.* TO 'backfiller'@'localhost';
DROP USER 'backfiller'@'localhost';
GRANT USAGE ON *.* TO 'test_setup'@'localhost';
DROP USER 'test_setup'@'localhost';

-- Storage Authority
GRANT SELECT,INSERT,UPDATE ON authz TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON pendingAuthorizations TO 'sa'@'localhost';
GRANT SELECT(id,Lockcol) ON pendingAuthorizations TO 'sa'@'localhost';
GRANT SELECT,INSERT ON certificates TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'localhost';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'localhost';
GRANT SELECT,INSERT ON sctReceipts TO 'sa'@'localhost';
GRANT SELECT,INSERT ON deniedCSRs TO 'sa'@'localhost';
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
GRANT SELECT,INSERT ON deniedCSRs TO 'revoker'@'localhost';

-- External Cert Importer
GRANT SELECT,INSERT,UPDATE,DELETE ON identifierData TO 'importer'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON externalCerts TO 'importer'@'localhost';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'localhost';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'localhost';
GRANT SELECT ON fqdnSets TO 'mailer'@'localhost';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'localhost';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'localhost';
