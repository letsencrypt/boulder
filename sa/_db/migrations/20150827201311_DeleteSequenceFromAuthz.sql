
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `authz` DROP COLUMN `sequence`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE `authz` ADD COLUMN `sequence` bigint(20) DEFAULT NULL;
