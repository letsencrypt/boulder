-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `authz2` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `identifierType` tinyint(4) NOT NULL,
  `identifierValue` varchar(255) NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `status` tinyint(4) NOT NULL,
  `expires` datetime NOT NULL,
  `challenges` tinyint(4) NOT NULL,
  `attempted` tinyint(4) DEFAULT NULL,
  `attemptedAt` datetime DEFAULT NULL,
  `token` binary(32) NOT NULL,
  `validationError` mediumblob DEFAULT NULL,
  `validationRecord` mediumblob DEFAULT NULL,
  `certificateProfileName` varchar(32) DEFAULT NULL,
  `created` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `regID_expires_idx` (`registrationID`,`status`,`expires`),
  KEY `regID_identifier_status_expires_idx` (`registrationID`,`identifierType`,`identifierValue`,`status`,`expires`),
  KEY `expires_idx` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `blockedKeys` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `keyHash` binary(32) NOT NULL,
  `added` datetime NOT NULL,
  `source` tinyint(4) NOT NULL,
  `comment` varchar(255) DEFAULT NULL,
  `revokedBy` bigint(20) DEFAULT 0,
  `extantCertificatesChecked` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `keyHash` (`keyHash`),
  KEY `extantCertificatesChecked_idx` (`extantCertificatesChecked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `certificateStatus` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `subscriberApproved` tinyint(1) DEFAULT 0,
  `status` varchar(255) NOT NULL,
  `ocspLastUpdated` datetime NOT NULL,
  `revokedDate` datetime NOT NULL,
  `revokedReason` int(11) NOT NULL,
  `lastExpirationNagSent` datetime NOT NULL,
  `LockCol` bigint(20) DEFAULT 0,
  `ocspResponse` blob DEFAULT NULL,
  `notAfter` datetime DEFAULT NULL,
  `isExpired` tinyint(1) DEFAULT 0,
  `issuerID` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `isExpired_ocspLastUpdated_idx` (`isExpired`,`ocspLastUpdated`),
  KEY `notAfter_idx` (`notAfter`),
  KEY `serial` (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `certificates` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `digest` varchar(255) NOT NULL,
  `der` mediumblob NOT NULL,
  `issued` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `regId_certificates_idx` (`registrationID`) COMMENT 'Common lookup',
  KEY `issued_idx` (`issued`),
  KEY `serial` (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `crlShards` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `issuerID` bigint(20) NOT NULL,
  `idx` int(10) unsigned NOT NULL,
  `thisUpdate` datetime DEFAULT NULL,
  `nextUpdate` datetime DEFAULT NULL,
  `leasedUntil` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `shardID` (`issuerID`,`idx`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `crls` (
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime NOT NULL,
  `crl` varchar(255) NOT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `fqdnSets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `setHash` binary(32) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `issued` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `setHash_issued_idx` (`setHash`,`issued`),
  KEY `serial` (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `incidents` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `serialTable` varchar(128) NOT NULL,
  `url` varchar(1024) NOT NULL,
  `renewBy` datetime NOT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `issuedNames` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `reversedName` varchar(640) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `notBefore` datetime NOT NULL,
  `serial` varchar(255) NOT NULL,
  `renewal` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `reversedName_notBefore_Idx` (`reversedName`,`notBefore`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `keyHashToSerial` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `keyHash` binary(32) NOT NULL,
  `certNotAfter` datetime NOT NULL,
  `certSerial` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_keyHash_certserial` (`keyHash`,`certSerial`),
  KEY `keyHash_certNotAfter` (`keyHash`,`certNotAfter`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `orderFqdnSets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `setHash` binary(32) NOT NULL,
  `orderID` bigint(20) NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `expires` datetime NOT NULL,
  `created` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `setHash_expires_idx` (`setHash`,`expires`),
  KEY `orderID_idx` (`orderID`),
  KEY `orderFqdnSets_registrationID_registrations` (`registrationID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `orders` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `expires` datetime NOT NULL,
  `error` mediumblob DEFAULT NULL,
  `certificateSerial` varchar(255) DEFAULT NULL,
  `beganProcessing` tinyint(1) NOT NULL DEFAULT 0,
  `created` datetime NOT NULL,
  `certificateProfileName` varchar(32) DEFAULT NULL,
  `replaces` varchar(255) DEFAULT NULL,
  `authzs` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `reg_expires` (`registrationID`,`expires`),
  KEY `regID_created_idx` (`registrationID`,`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `overrides` (
  `limitEnum` tinyint(4) unsigned NOT NULL,
  `bucketKey` varchar(255) NOT NULL,
  `comment` varchar(255) NOT NULL,
  `periodNS` bigint(20) unsigned NOT NULL,
  `count` int(10) unsigned NOT NULL,
  `burst` int(10) unsigned NOT NULL,
  `updatedAt` datetime NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  UNIQUE KEY `limitEnum_bucketKey` (`limitEnum`,`bucketKey`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `paused` (
  `registrationID` bigint(20) unsigned NOT NULL,
  `identifierType` tinyint(4) NOT NULL,
  `identifierValue` varchar(255) NOT NULL,
  `pausedAt` datetime NOT NULL,
  `unpausedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`registrationID`,`identifierValue`,`identifierType`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- Note: This table's name is a historical artifact and it is now
-- used to store linting certificates, not precertificates.
-- See #6807.
CREATE TABLE `precertificates` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `der` mediumblob NOT NULL,
  `issued` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `regId_precertificates_idx` (`registrationID`),
  KEY `issued_precertificates_idx` (`issued`),
  KEY `serial` (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `registrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `jwk` mediumblob NOT NULL,
  `jwk_sha256` varchar(255) NOT NULL,
  `agreement` varchar(255) NOT NULL,
  `LockCol` bigint(20) NOT NULL DEFAULT 0,
  `createdAt` datetime NOT NULL,
  `status` varchar(255) NOT NULL DEFAULT 'valid',
  PRIMARY KEY (`id`),
  UNIQUE KEY `jwk_sha256` (`jwk_sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `replacementOrders` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `orderID` bigint(20) NOT NULL,
  `orderExpires` datetime NOT NULL,
  `replaced` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `serial_idx` (`serial`),
  KEY `orderID_idx` (`orderID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `revokedCertificates` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `issuerID` bigint(20) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `notAfterHour` datetime NOT NULL,
  `shardIdx` bigint(20) NOT NULL,
  `revokedDate` datetime NOT NULL,
  `revokedReason` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `issuerID_shardIdx_notAfterHour_idx` (`issuerID`,`shardIdx`,`notAfterHour`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `serials` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `created` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `serial` (`serial`),
  KEY `regId_serials_idx` (`registrationID`),
  CONSTRAINT `regId_serials` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

-- First set of tables have foreign key constraints, so are dropped first.
DROP TABLE `serials`;

DROP TABLE `authz2`;
DROP TABLE `blockedKeys`;
DROP TABLE `certificateStatus`;
DROP TABLE `certificatesPerName`;
DROP TABLE `certificates`;
DROP TABLE `fqdnSets`;
DROP TABLE `incidents`;
DROP TABLE `issuedNames`;
DROP TABLE `keyHashToSerial`;
DROP TABLE `newOrdersRL`;
DROP TABLE `orderFqdnSets`;
DROP TABLE `orderToAuthz2`;
DROP TABLE `orders`;
DROP TABLE `precertificates`;
DROP TABLE `registrations`;
DROP TABLE `requestedNames`;
