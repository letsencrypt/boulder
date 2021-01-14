
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE authz2 DROP INDEX token, ALGORITHM=NOCOPY, LOCK=NONE;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE authz2_new ADD UNIQUE INDEX token (token), ALGORITHM=NOCOPY;
