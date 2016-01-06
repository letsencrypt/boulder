-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.

USE mysql;

DROP PROCEDURE IF EXISTS dropusers;

DELIMITER //

CREATE PROCEDURE dropusers ()
    BEGIN

        DECLARE CONTINUE HANDLER FOR SQLSTATE 'HY000' BEGIN END;

        create user 'policy'@'localhost';
        create user 'sa'@'localhost';
        create user 'ocsp_resp'@'localhost';
        create user 'revoker'@'localhost';
        create user 'importer'@'localhost';
        create user 'mailer'@'localhost';
        create user 'cert_checker'@'localhost';
        create user 'ocsp_update'@'localhost';
        create user 'test_setup'@'localhost';

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
        GRANT USAGE ON *.* TO 'test_setup'@'localhost';
        DROP USER 'test_setup'@'localhost';

    END;
    //

DELIMITER ;

CALL dropusers();

-- MariaDB seems to have the NO_AUTO_CREATE_USER flag set. Later in the create_db.sh, removing this flag will get users created.
-- This flag became default in 10.1.7 of MariaDB.  This will also turn off the NO_ENGINE_SUBSTITUTION flag.

SET GLOBAL sql_mode = '';
