
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
RENAME TABLE `pending_authz` to `pendingAuthorizations`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
RENAME TABLE `pendingAuthorizations` to `pending_authz`;

