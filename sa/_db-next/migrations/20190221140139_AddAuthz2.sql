
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `authz2` (
    `id` BIGINT(20) PRIMARY KEY AUTO_INCREMENT,
    `identifierType` SMALLINT NOT NULL,
    `identifierValue` VARCHAR(255) NOT NULL,
    `registrationID` BIGINT(20) NOT NULL,
    `status` SMALLINT NOT NULL,
    `expires` DATETIME NOT NULL,
    `challenges` BIT(8) NOT NULL,
    `attempted` SMALLINT DEFAULT NULL,
    `attemptedAt` DATETIME DEFAULT NULL,
    `token` BINARY(32) UNIQUE NOT NULL,
    `validationError` MEDIUMBLOB NOT NULL,
    `validationRecord` MEDIUMBLOB NOT NULL,
    KEY `regID_expires_idx` (`registrationID`, `status`, `expires`),
    KEY `regID_identifier_status_expires_idx` (`registrationID`, `identifierType`, `identifierValue`, `status`, `expires`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `authz`;
