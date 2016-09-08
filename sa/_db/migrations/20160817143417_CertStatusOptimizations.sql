
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificateStatus` ADD COLUMN `notAfter` DATETIME DEFAULT NULL;
ALTER TABLE `certificateStatus` ADD COLUMN `isExpired` BOOL DEFAULT FALSE;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `certificateStatus` DROP COLUMN `notAfter`;
ALTER TABLE `certificateStatus` DROP COLUMN `isExpired`;
