
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificateStatus` MODIFY `subscriberApproved` tinyint(1) NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `status` varchar(255) NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `ocspLastUpdated` datetime NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `revokedDate` datetime NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `revokedReason` int(11) NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `lastExpirationNagSent` datetime NOT NULL;
ALTER TABLE `certificateStatus` MODIFY `LockCol` bigint(20) NOT NULL;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `certificateStatus` MODIFY `subscriberApproved` tinyint(1) DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `status` varchar(255) DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `ocspLastUpdated` datetime DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `revokedDate` datetime DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `revokedReason` int(11) DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `lastExpirationNagSent` datetime DEFAULT NULL;
ALTER TABLE `certificateStatus` MODIFY `LockCol` bigint(20) DEFAULT NULL;
