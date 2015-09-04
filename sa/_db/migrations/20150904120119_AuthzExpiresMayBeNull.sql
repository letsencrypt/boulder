
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `authz` MODIFY `expires` datetime DEFAULT NULL;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE `authz` MODIFY `expires` datetime NOT NULL;
