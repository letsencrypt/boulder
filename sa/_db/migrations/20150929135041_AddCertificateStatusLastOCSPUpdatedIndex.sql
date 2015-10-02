
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE INDEX `ocspLastUpdated_certificateStatus_idx` on `certificateStatus` (`ocspLastUpdated`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX `ocspLastUpdated_certificateStatus_idx` on `certificateStatus`;
