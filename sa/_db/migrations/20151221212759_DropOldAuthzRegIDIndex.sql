
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DROP INDEX `regId_idx` ON `authz`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
CREATE INDEX `regId_idx` ON `authz` (`registrationID`);
