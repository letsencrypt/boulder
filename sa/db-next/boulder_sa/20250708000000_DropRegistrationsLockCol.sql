-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `registrations` DROP COLUMN `LockCol`;

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `registrations` ADD COLUMN `LockCol` BIGINT(20) NOT NULL DEFAULT 0;
