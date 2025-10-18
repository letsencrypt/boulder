-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE blockedKeys
  ADD INDEX blockedKeys_extantCertificatesChecked_added_idx
    (extantCertificatesChecked, added);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE blockedKeys
  DROP INDEX blockedKeys_extantCertificatesChecked_added_idx;
