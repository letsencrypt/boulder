
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `registrations` MODIFY `contact` varchar(255) NOT NULL;
ALTER TABLE `registrations` MODIFY `agreement` varchar(255) NOT NULL;
ALTER TABLE `registrations` MODIFY `LockCol` bigint(20) NOT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `registrations` MODIFY `contact` varchar(255) DEFAULT NULL;
ALTER TABLE `registrations` MODIFY `agreement` varchar(255) DEFAULT NULL;
ALTER TABLE `registrations` MODIFY `LockCol` bigint(20) DEFAULT NULL;
