
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `authz` MODIFY `identifier` varchar(255) NOT NULL;

ALTER TABLE `authz` DROP FOREIGN KEY `regId_authz`;
ALTER TABLE `authz` MODIFY `registrationID` bigint(20) NOT NULL;
ALTER TABLE `authz` ADD CONSTRAINT `regId_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE `authz` MODIFY `status` varchar(255) NOT NULL;
ALTER TABLE `authz` MODIFY `expires` datetime NOT NULL;
ALTER TABLE `authz` MODIFY `combinations` varchar(255) NOT NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `authz` MODIFY `identifier` varchar(255) DEFAULT NULL;

ALTER TABLE `authz` DROP FOREIGN KEY `regId_authz`;
ALTER TABLE `authz` MODIFY `registrationID` bigint(20) DEFAULT NULL;
ALTER TABLE `authz` ADD CONSTRAINT `regId_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE `authz` MODIFY `status` varchar(255) DEFAULT NULL;
ALTER TABLE `authz` MODIFY `expires` datetime DEFAULT NULL;
ALTER TABLE `authz` MODIFY `combinations` varchar(255) DEFAULT NULL;
