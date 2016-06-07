-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.

USE mysql;

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
GRANT USAGE ON *.* TO 'purger'@'localhost';
DROP USER 'purger'@'localhost';
GRANT USAGE ON *.* TO 'backfiller'@'localhost';
DROP USER 'backfiller'@'localhost';
GRANT USAGE ON *.* TO 'test_setup'@'localhost';
DROP USER 'test_setup'@'localhost';
