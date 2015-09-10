
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `certificates` DROP FOREIGN KEY `regId_certificates`;
ALTER TABLE `certificates` MODIFY `registrationID` bigint(20) NOT NULL;
ALTER TABLE `certificates` ADD CONSTRAINT `regId_certificates` FOREIGN KEY (`registrationID`)  REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE `certificates` MODIFY `digest` varchar(255) NOT NULL;
ALTER TABLE `certificates` MODIFY `der` mediumblob NOT NULL;
ALTER TABLE `certificates` MODIFY `issued` datetime NOT NULL;
ALTER TABLE `certificates` MODIFY `expires` datetime NOT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE `certificates` DROP FOREIGN KEY `regId_certificates`;
ALTER TABLE `certificates` MODIFY `registrationID` bigint(20) DEFAULT NULL;
ALTER TABLE `certificates` ADD CONSTRAINT `regId_certificates` FOREIGN KEY (`registrationID`)  REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE `certificates` MODIFY `digest` varchar(255) DEFAULT NULL;
ALTER TABLE `certificates` MODIFY `der` mediumblob DEFAULT NULL;
ALTER TABLE `certificates` MODIFY `issued` datetime DEFAULT NULL;
ALTER TABLE `certificates` MODIFY `expires` datetime DEFAULT NULL;

