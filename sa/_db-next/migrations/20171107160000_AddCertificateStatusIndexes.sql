-- +goose Up
ALTER TABLE certificateStatus
       ADD INDEX `isExpired_ocspLastUpdated_idx` (`isExpired`, `ocspLastUpdated`),
       ADD INDEX `notAfter_idx` (`notAfter`),
       DROP INDEX `status_certificateStatus_idx`,
       DROP INDEX `ocspLastUpdated_certificateStatus_idx`;

-- +goose Down
ALTER TABLE certificateStatus
       DROP INDEX `isExpired_ocspLastUpdated_idx`,
       DROP INDEX `notAfter_idx`,
       ADD INDEX `ocspLastUpdated_certificateStatus_idx` (`ocspLastUpdated`),
       ADD INDEX `status_certificateStatus_idx` (`status`);
