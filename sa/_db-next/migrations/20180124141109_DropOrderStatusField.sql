
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `orders` DROP COLUMN `status`;
ALTER TABLE `orders` ADD COLUMN `beganProcessing` BOOL NOT NULL DEFAULT FALSE;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `orders` ADD COLUMN `status` varchar(255) NOT NULL;
