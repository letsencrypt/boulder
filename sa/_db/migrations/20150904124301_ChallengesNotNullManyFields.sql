
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `challenges` MODIFY `LockCol` bigint(20) NOT NULL;
ALTER TABLE `challenges` MODIFY `uri` varchar(255) NOT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `challenges` MODIFY `LockCol` bigint(20) DEFAULT NULL;
ALTER TABLE `challenges` MODIFY `uri` varchar(255) DEFAULT NULL;
