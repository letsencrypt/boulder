
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE `authorizations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token` mediumblob,
  `identifierValue` varchar(255) NOT NULL,
  `identifierType` int NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `status` int NOT NULL,
  `expires` datetime NOT NULL,
  `allowedChallenges` tinyint,
  `validated` datetime NOT NULL,
  `validationRecord` mediumblob,
  `error` mediumblob,
  `thumbprint` mediumblob,

  PRIMARY KEY (`id`),
  UNIQUE KEY `identifier_key` (`identifierType`, `identifierValue`),

  KEY `registrationID_status_expires_idx` (`registrationID`, `status`, `expires`),
  CONSTRAINT `registrationID_status_expires_idx` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,

  KEY `identifierType_identifierValue_status_registrationID_expires_idx` (`identifierType`, `identifierValue`, `status`, `registrationID`, `expires`),
  CONSTRAINT `identifierType_identifierValue_status_registrationID_expires_idx` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `authorizations`;
