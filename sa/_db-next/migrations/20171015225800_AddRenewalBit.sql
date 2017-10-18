
-- +goose Up
ALTER TABLE issuedNames
       ADD COLUMN renewal TINYINT(1) NOT NULL DEFAULT 0,
       ADD INDEX `reversedName_renewal_notBefore_Idx` (`reversedName`,`renewal`,`notBefore`);
;

-- +goose Down
ALTER TABLE issuedNames
       DROP COLUMN renewal,
       DROP INDEX `reversedName_renewal_notBefore_Idx`;
;
