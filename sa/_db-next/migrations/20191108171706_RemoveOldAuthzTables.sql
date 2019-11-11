
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE `authz`;
DROP TABLE `pendingAuthorizations`;
DROP TABLE `orderToAuthz`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `authz` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `status` varchar(255) NOT NULL,
  `expires` datetime DEFAULT NULL,
  `combinations` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `registrationID_identifier_status_expires_authz_idx` (`registrationID`,`identifier`,`status`,`expires`),
  CONSTRAINT `regId_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `pendingAuthorizations` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `status` varchar(255) NOT NULL,
  `expires` datetime DEFAULT NULL,
  `combinations` varchar(255) NOT NULL,
  `LockCol` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `identifier_registrationID_status_expires_idx` (`identifier`,`registrationID`,`status`,`expires`),
  KEY `registrationID_status_expires_idx` (`registrationID`,`status`,`expires`),
  CONSTRAINT `regId_pending_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `orderToAuthz` (
  `orderID` bigint(20) NOT NULL,
  `authzID` varchar(255) NOT NULL,
  PRIMARY KEY (`orderID`,`authzID`),
  KEY `authzID` (`authzID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
