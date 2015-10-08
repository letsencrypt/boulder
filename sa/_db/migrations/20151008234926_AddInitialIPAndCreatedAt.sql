
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `registrations` ADD COLUMN (
  `initialIP` BINARY(16) NOT NULL DEFAULT "",
  `createdAt` DATETIME NOT NULL
);
CREATE INDEX `initialIP_createdAt` on `registrations` (`initialIP`, `createdAt`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX `initialIP_createdAt` on `registrations`;
