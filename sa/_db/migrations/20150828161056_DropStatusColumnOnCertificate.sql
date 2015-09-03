
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificates` DROP COLUMN `status`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `certificates` ADD COLUMN `status` varchar(255) DEFAULT NULL;
