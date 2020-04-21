
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE blockedKeys ADD `revokedBy` BIGINT(20) DEFAULT 0;
ALTER TABLE blockedKeys ADD `extantCertificatesChecked` BOOLEAN DEFAULT FALSE;
CREATE INDEX `extantCertificatesChecked_idx` ON blockedKeys (`extantCertificatesChecked`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE blockedKeys DROP `revokedBy`;
ALTER TABLE blockedKeys DROP `extantCertificatesChecked`;
DROP INDEX `extantCertificatesChecked_idx` ON blockedKeys;
