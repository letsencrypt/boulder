
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE `authorizations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `identifierValue` varchar(255) DEFAULT NULL,
  `identifierType` int DEFAULT NULL,
  `registrationID` bigint(20) DEFAULT NULL,
  `status` int DEFAULT 0,
  `expires` datetime DEFAULT NULL,
  `combinations` varchar(255) DEFAULT NULL,
  `sequence` bigint(20) DEFAULT NULL,
  `validated` datetime DEFAULT NULL,
  `validationRecord` mediumblob,
  `error` mediumblob,
  `thumbprint` mediumblob,

  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  UNIQUE KEY `identifier_key` (`identifierType`, `identifierValue`),

  KEY `regId_idx` (`registrationID`) COMMENT 'Common lookup',
  CONSTRAINT `regId_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `authorizations`;
