
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE INDEX `regId_expires_idx` on `pendingAuthorizations` (`registrationID`, `expires`);
DROP INDEX `regId_idx` on `pendingAuthorizations`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE INDEX `regId_idx` on `pendingAuthorizations` (`registrationID`);
DROP INDEX `regId_expires_idx` on `pendingAuthorizations`;
