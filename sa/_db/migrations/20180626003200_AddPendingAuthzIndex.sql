
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `pendingAuthorizations`
  ADD INDEX `identifier_registrationID_status_expires_idx` (
    `identifier`, `registrationID`, `status`, `expires`),
  ADD INDEX `registrationID_status_expires_idx` (
    `registrationID`, `status`, `expires`),
  DROP INDEX `regId_expires_idx`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `pendingAuthorizations`
  DROP INDEX `identifier_registrationID_status_expires_idx`,
  DROP INDEX `registrationID_status_expires_idx`,
  ADD INDEX `regId_expires_idx` (`registrationID`,`expires`);
