
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `challenges` ADD COLUMN (`keyAuthorization` varchar(255));
ALTER TABLE `challenges` DROP COLUMN `validation`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `challenges` DROP COLUMN `keyAuthorization`;
ALTER TABLE `challenges` ADD COLUMN (`validation` mediumblob);
