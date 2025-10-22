-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE paused
  ADD INDEX paused_regID_unpausedAt_identifierType_identifierValue_idx
    (registrationID, unpausedAt, identifierType, identifierValue);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE paused
  DROP INDEX paused_regID_unpausedAt_identifierType_identifierValue_idx;
