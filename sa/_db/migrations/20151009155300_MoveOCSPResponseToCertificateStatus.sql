
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificateStatus` ADD COLUMN (`ocspResponse` blob);
CREATE INDEX `status_certificateStatus_idx` on `certificateStatus` (`status`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX `status_certificateStatus_idx` on `certificateStatus`;
ALTER TABLE `certificateStatus` DROP COLUMN `ocspResponse`;
