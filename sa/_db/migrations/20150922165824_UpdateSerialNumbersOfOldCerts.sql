-- This bit of weirdness is because we had to change how long our serial ids
-- were. Fortunately, zero padding them works fine. For some details, see
-- https://github.com/letsencrypt/boulder/issues/834

-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
UPDATE certificates SET serial = CONCAT('0000', serial) WHERE length(serial) = 32;
UPDATE certificateStatus SET serial = CONCAT('0000', serial) WHERE length(serial) = 32;
UPDATE ocspResponses SET serial = CONCAT('0000', serial) WHERE length(serial) = 32;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
UPDATE certificates SET serial = SUBSTR(serial, 5) WHERE length(serial) = 36 AND serial LIKE '0000%';
UPDATE certificateStatus SET serial = SUBSTR(serial, 5) WHERE length(serial) = 36 AND serial LIKE '0000%';
UPDATE ocspResponses SET serial = SUBSTR(serial, 5) WHERE length(serial) = 36 AND serial LIKE '0000%';
