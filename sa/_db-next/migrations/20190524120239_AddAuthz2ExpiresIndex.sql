
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE INDEX `expires_idx` ON `authz2` (`expires`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP INDEX `expires_idx` ON `authz2`;
