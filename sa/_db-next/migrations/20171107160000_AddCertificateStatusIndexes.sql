-- +goose Up
ALTER TABLE certificateStatus
       ADD INDEX `isExpired_ocspLastUpdated_Idx` (`isExpired`, `ocspLastUpdated`),
       ADD INDEX `notAfter_Idx` (`notAfter`),
       DROP INDEX `status_certificateStatus_idx`,
       DROP INDEX `ocspLastUpdated_certificateStatus_idx`;

-- +goose Down
ALTER TABLE certificateStatus
       DROP INDEX `isExpired_ocspLastUpdated_Idx`,
       DROP INDEX `notAfter_Idx`,
       ADD INDEX `ocspLastUpdated_certificateStatus_idx` (`ocspLastUpdated`),
       ADD INDEX `status_certificateStatus_idx` (`status`);
