
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificates` ADD INDEX `issued` (`issued`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `certificates` DROP INDEX `issued`;
