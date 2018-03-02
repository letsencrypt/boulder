
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `orders`
  ADD COLUMN `created` DATETIME NOT NULL,
  ADD INDEX `regID_created_idx` (`registrationID`, `created`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `orders`
  DROP COLUMN `created`,
  DROP INDEX `regID_created_idx`;
