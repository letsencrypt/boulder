
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `orders`
  ADD INDEX `regID_error_beganProcessing_certSerial_expires`
  (`registrationID`, `error`(1), `beganProcessing`, `certificateSerial`, `expires`);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `orders`
  DROP INDEX `regID_error_beganProcessing_certSerial_expires`;
