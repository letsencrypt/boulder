
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE INDEX `registrationID_identifier_status_expires_authz_idx` on authz (`registrationID`, `identifier`, `status`, `expires` desc);


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX `registrationID_identifier_status_expires_authz_idx` on `authz`;
