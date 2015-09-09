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

-- Storage Authority
CREATE USER `sa`@`%` IDENTIFIED BY 'password';
GRANT SELECT,INSERT,UPDATE ON authz TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE,DELETE ON pendingAuthorizations TO 'sa'@'%';
GRANT SELECT,INSERT ON certificates TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'%';
GRANT SELECT,INSERT ON deniedCSRs TO 'sa'@'%';
GRANT INSERT ON ocspResponses TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON challenges TO 'sa'@'%';

-- OCSP Responder
CREATE USER `ocsp_resp`@`%` IDENTIFIED BY 'password';
GRANT SELECT ON ocspResponses TO 'ocsp_resp'@'%';

-- OCSP Generator Tool (Updater)
CREATE USER `ocsp_update`@`%` IDENTIFIED BY 'password';
GRANT INSERT ON ocspResponses TO 'ocsp_update'@'%';
GRANT SELECT ON certificates TO 'ocsp_update'@'%';
GRANT SELECT,UPDATE ON certificateStatus TO 'ocsp_update'@'%';

-- Revoker Tool
CREATE USER `revoker`@`%` IDENTIFIED BY 'password';
GRANT SELECT ON registrations TO 'revoker'@'%';
GRANT SELECT ON certificates TO 'revoker'@'%';
GRANT SELECT,INSERT ON deniedCSRs TO 'revoker'@'%';

-- External Cert Importer
CREATE USER `importer`@`%` IDENTIFIED BY 'password';
GRANT SELECT,INSERT,UPDATE,DELETE ON identifierData TO 'importer'@'%';
GRANT SELECT,INSERT,UPDATE,DELETE ON externalCerts TO 'importer'@'%';
