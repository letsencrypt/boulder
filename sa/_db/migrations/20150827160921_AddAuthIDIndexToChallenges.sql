
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE INDEX `authorizationID_challenges_idx` on `challenges` (`authorizationID`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX `authorizationID_challenges_idx` on `challenges`;

