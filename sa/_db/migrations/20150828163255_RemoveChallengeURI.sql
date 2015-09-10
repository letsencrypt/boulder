
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `challenges` DROP COLUMN `uri`;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `challenges` ADD COLUMN (
  `uri` varchar(255)
);
