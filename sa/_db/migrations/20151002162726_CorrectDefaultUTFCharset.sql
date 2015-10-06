
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Adjust utf8mb4 is the real 4-byte UTF-8. But to fit the contact column in an
-- index entirely, we need to adjust 255 down to 191.
ALTER TABLE `registrations` MODIFY COLUMN contact varchar(191) CHARACTER SET utf8mb4 NOT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `registrations` MODIFY COLUMN contact varchar(255) CHARACTER SET utf8 NOT NULL;
