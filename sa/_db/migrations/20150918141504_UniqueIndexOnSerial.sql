
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE UNIQUE INDEX `serial_idx` on `certificates` (`serial`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP INDEX `serial_idx` on `certificates`;
