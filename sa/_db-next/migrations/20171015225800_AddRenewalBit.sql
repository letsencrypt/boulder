
-- +goose Up
ALTER TABLE issuedNames
       ADD COLUMN renewal TINYINT(1) NOT NULL DEFAULT 0,
       ADD INDEX `reversedName_renewal_notBefore_Idx` (`reversedName`,`renewal`,`notBefore`),
       DROP INDEX `reversedName_notBefore_Idx`
;

-- +goose Down
ALTER TABLE issuedNames
       DROP COLUMN renewal,
       ADD INDEX `reversedName_notBefore_Idx` (`reversedName`,`notBefore`),
       DROP INDEX `reversedName_renewal_notBefore_Idx`
;
