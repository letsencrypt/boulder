-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.
GRANT USAGE ON *.* TO 'policy'@'boulder';
DROP USER 'policy'@'boulder';
GRANT USAGE ON *.* TO 'sa'@'boulder';
DROP USER 'sa'@'boulder';
GRANT USAGE ON *.* TO 'ocsp_resp'@'boulder';
DROP USER 'ocsp_resp'@'boulder';
GRANT USAGE ON *.* TO 'ocsp_update'@'boulder';
DROP USER 'ocsp_update'@'boulder';
GRANT USAGE ON *.* TO 'revoker'@'boulder';
DROP USER 'revoker'@'boulder';
GRANT USAGE ON *.* TO 'importer'@'boulder';
DROP USER 'importer'@'boulder';
GRANT USAGE ON *.* TO 'mailer'@'boulder';
DROP USER 'mailer'@'boulder';
GRANT USAGE ON *.* TO 'cert_checker'@'boulder';
DROP USER 'cert_checker'@'boulder';
GRANT USAGE ON *.* TO 'backfiller'@'boulder';
DROP USER 'backfiller'@'boulder';
