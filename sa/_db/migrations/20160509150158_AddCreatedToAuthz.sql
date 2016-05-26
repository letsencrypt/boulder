
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `authz` ADD COLUMN `created` DATETIME DEFAULT NULL;
ALTER TABLE `pendingAuthorizations` ADD COLUMN `created` DATETIME DEFAULT NULL;
CREATE INDEX `authz_identifier_created_status` on `authz` (`identifier`, `created`, `status`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `authz` DROP COLUMN `created`;
ALTER TABLE `pendingAuthorizations` DROP COLUMN `created`;
DROP INDEX `authz_identifier_created_status` on `authz`;
