
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `challenges` DROP COLUMN `accountKey`;
ALTER TABLE `challenges` DROP COLUMN `tls`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `challenges` ADD COLUMN (
  `accountKey` mediumBlob
);

ALTER TABLE `challenges` ADD COLUMN (
  `tls` tinyint(1) DEFAULT NULL
);
