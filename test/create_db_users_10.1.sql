
-- only run in 10.1 versions of MariaDB

create user if not exists 'policy'@'localhost';
create user if not exists 'sa'@'localhost';
create user if not exists 'ocsp_resp'@'localhost';
create user if not exists 'revoker'@'localhost';
create user if not exists 'importer'@'localhost';
create user if not exists 'mailer'@'localhost';
create user if not exists 'cert_checker'@'localhost';
create user if not exists 'ocsp_update'@'localhost';
create user if not exists 'test_setup'@'localhost';

