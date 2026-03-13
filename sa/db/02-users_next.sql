USE boulder_sa_next;

CREATE USER IF NOT EXISTS 'policy'@'%';
CREATE USER IF NOT EXISTS 'sa'@'%';
CREATE USER IF NOT EXISTS 'sa_ro'@'%';
CREATE USER IF NOT EXISTS 'revoker'@'%';
CREATE USER IF NOT EXISTS 'importer'@'%';
CREATE USER IF NOT EXISTS 'mailer'@'%';
CREATE USER IF NOT EXISTS 'cert_checker'@'%';
CREATE USER IF NOT EXISTS 'test_setup'@'%';
CREATE USER IF NOT EXISTS 'badkeyrevoker'@'%';
CREATE USER IF NOT EXISTS 'proxysql'@'%';

-- Storage Authority
GRANT SELECT,INSERT ON certificates TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON certificateStatus TO 'sa'@'%';
GRANT SELECT,INSERT ON issuedNames TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON registrations TO 'sa'@'%';
GRANT SELECT,INSERT on fqdnSets TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON orders TO 'sa'@'%';
GRANT SELECT,INSERT,DELETE ON orderFqdnSets TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON authz2 TO 'sa'@'%';
GRANT INSERT,SELECT ON serials TO 'sa'@'%';
GRANT SELECT,INSERT ON precertificates TO 'sa'@'%';
GRANT SELECT,INSERT ON keyHashToSerial TO 'sa'@'%';
GRANT SELECT,INSERT ON blockedKeys TO 'sa'@'%';
GRANT SELECT ON incidents TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON crlShards TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON revokedCertificates TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON replacementOrders TO 'sa'@'%';
GRANT SELECT,INSERT,UPDATE ON overrides TO 'sa'@'%';
-- Tests need to be able to remove rows from this table, so DELETE,DROP is necessary.
GRANT SELECT,INSERT,UPDATE,DELETE,DROP ON paused TO 'sa'@'%';

GRANT SELECT ON certificates TO 'sa_ro'@'%';
GRANT SELECT ON certificateStatus TO 'sa_ro'@'%';
GRANT SELECT ON issuedNames TO 'sa_ro'@'%';
GRANT SELECT ON registrations TO 'sa_ro'@'%';
GRANT SELECT on fqdnSets TO 'sa_ro'@'%';
GRANT SELECT ON orders TO 'sa_ro'@'%';
GRANT SELECT ON orderFqdnSets TO 'sa_ro'@'%';
GRANT SELECT ON authz2 TO 'sa_ro'@'%';
GRANT SELECT ON serials TO 'sa_ro'@'%';
GRANT SELECT ON precertificates TO 'sa_ro'@'%';
GRANT SELECT ON keyHashToSerial TO 'sa_ro'@'%';
GRANT SELECT ON blockedKeys TO 'sa_ro'@'%';
GRANT SELECT ON incidents TO 'sa_ro'@'%';
GRANT SELECT ON crlShards TO 'sa_ro'@'%';
GRANT SELECT ON revokedCertificates TO 'sa_ro'@'%';
GRANT SELECT ON replacementOrders TO 'sa_ro'@'%';
GRANT SELECT ON paused TO 'sa_ro'@'%';
GRANT SELECT ON overrides TO 'sa_ro'@'%';

-- Revoker Tool
GRANT SELECT,UPDATE ON registrations TO 'revoker'@'%';
GRANT SELECT ON certificates TO 'revoker'@'%';
GRANT SELECT ON precertificates TO 'revoker'@'%';
GRANT SELECT ON keyHashToSerial TO 'revoker'@'%';
GRANT SELECT,UPDATE ON blockedKeys TO 'revoker'@'%';

-- Expiration mailer
GRANT SELECT ON certificates TO 'mailer'@'%';
GRANT SELECT ON registrations TO 'mailer'@'%';
GRANT SELECT,UPDATE ON certificateStatus TO 'mailer'@'%';
GRANT SELECT ON fqdnSets TO 'mailer'@'%';

-- Cert checker
GRANT SELECT ON certificates TO 'cert_checker'@'%';
GRANT SELECT ON authz2 TO 'cert_checker'@'%';
GRANT SELECT ON precertificates TO 'cert_checker'@'%';

-- Bad Key Revoker
GRANT SELECT,UPDATE ON blockedKeys TO 'badkeyrevoker'@'%';
GRANT SELECT ON keyHashToSerial TO 'badkeyrevoker'@'%';
GRANT SELECT ON certificateStatus TO 'badkeyrevoker'@'%';
GRANT SELECT ON precertificates TO 'badkeyrevoker'@'%';
GRANT SELECT ON registrations TO 'badkeyrevoker'@'%';

-- ProxySQL --
GRANT ALL PRIVILEGES ON monitor TO 'proxysql'@'%';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'%';

USE incidents_sa_next;

CREATE USER IF NOT EXISTS 'incidents_sa'@'%';
CREATE USER IF NOT EXISTS 'test_setup'@'%';

-- Storage Authority
GRANT SELECT ON * TO 'incidents_sa'@'%';

-- Test setup and teardown
GRANT ALL PRIVILEGES ON * to 'test_setup'@'%';
