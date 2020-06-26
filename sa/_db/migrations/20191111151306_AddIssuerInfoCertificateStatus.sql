
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE certificateStatus ADD `issuerID` BIGINT(20) DEFAULT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE certificateStatus DROP `issuerID`;
