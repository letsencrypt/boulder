
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `fqdnSets` MODIFY `id` BIGINT(20) NOT NULL AUTO_INCREMENT;
ALTER TABLE `issuedNames` MODIFY `id` BIGINT(20) NOT NULL AUTO_INCREMENT;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `fqdnSets` MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;
ALTER TABLE `issuedNames` MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;
