
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `challenges` ADD COLUMN (
  `authorizedKey` mediumblob
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `challenges` DROP COLUMN `authorizedKey`;
