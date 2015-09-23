-- This bit of weirdness is because we had to change how long our serial ids
-- were. Fortunately, zero padding them works fine. For some details, see
-- https://github.com/letsencrypt/boulder/issues/834

-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
UPDATE certificates SET serial = CONCAT('0000', serial);
UPDATE certificateStatus SET serial = CONCAT('0000', serial);
UPDATE ocspResponses SET serial = CONCAT('0000', serial);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
UPDATE certificates SET serial = SUBSTR(serial, 5);
UPDATE certificateStatus SET serial = SUBSTR(serial, 5);
UPDATE ocspResponses SET serial = SUBSTR(serial, 5);
