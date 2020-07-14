-- sa_db_users.sql is run by test/create_db.sh to create users for each
-- component with the appropriate permissions.

-- These lines require MariaDB 10.1+
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
CREATE USER IF NOT EXISTS 'janitor'@'localhost';
CREATE USER IF NOT EXISTS 'badkeyrevoker'@'localhost';

-- Storage Authority
GRANT SELECT,INSERT ON certificates TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'localhost';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON certificatesPerName TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON challenges TO 'sa'@'localhost';
GRANT SELECT,INSERT on fqdnSets TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON orders TO 'sa'@'localhost';
GRANT SELECT,INSERT ON requestedNames TO 'sa'@'localhost';
GRANT SELECT,INSERT,DELETE ON orderFqdnSets TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON authz2 TO 'sa'@'localhost';
GRANT SELECT,INSERT ON orderToAuthz2 TO 'sa'@'localhost';
GRANT INSERT,SELECT ON serials TO 'sa'@'localhost';
GRANT SELECT,INSERT ON precertificates TO 'sa'@'localhost';
GRANT SELECT,INSERT ON keyHashToSerial TO 'sa'@'localhost';
GRANT SELECT,INSERT ON blockedKeys TO 'sa'@'localhost';
GRANT SELECT,INSERT,UPDATE ON newOrdersRL TO 'sa'@'localhost';

-- OCSP Responder
GRANT SELECT ON certificateStatus TO 'ocsp_resp'@'localhost';

-- OCSP Generator Tool (Updater)
GRANT SELECT ON certificates TO 'ocsp_update'@'localhost';
GRANT SELECT,UPDATE ON certificateStatus TO 'ocsp_update'@'localhost';
GRANT SELECT ON precertificates TO 'ocsp_update'@'localhost';

-- Revoker Tool
GRANT SELECT ON registrations TO 'revoker'@'localhost';
GRANT SELECT ON certificates TO 'revoker'@'localhost';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'localhost';
GRANT SELECT ON registrations TO 'mailer'@'localhost';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'localhost';
GRANT SELECT ON fqdnSets TO 'mailer'@'localhost';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'localhost';

-- Expired authorization purger
GRANT SELECT,DELETE ON challenges TO 'purger'@'localhost';
GRANT SELECT,DELETE ON authz2 TO 'purger'@'localhost';

-- Janitor
GRANT SELECT,DELETE ON certificates TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON certificateStatus TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON certificatesPerName TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON sctReceipts TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON orders TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON requestedNames TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON orderFqdnSets TO 'janitor'@'localhost';
GRANT SELECT,DELETE ON orderToAuthz2 TO 'janitor'@'localhost';

-- Bad Key Revoker
GRANT SELECT,UPDATE ON blockedKeys TO 'badkeyrevoker'@'localhost';
GRANT SELECT ON keyHashToSerial TO 'badkeyrevoker'@'localhost';
GRANT SELECT ON certificateStatus TO 'badkeyrevoker'@'localhost';
GRANT SELECT ON precertificates TO 'badkeyrevoker'@'localhost';
GRANT SELECT ON registrations TO 'badkeyrevoker'@'localhost';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'localhost';
