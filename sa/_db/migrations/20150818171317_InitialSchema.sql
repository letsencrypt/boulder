
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `registrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `jwk` mediumblob NOT NULL,
  `jwk_sha256` varchar(255) NOT NULL,
  `contact` varchar(255) DEFAULT NULL,
  `agreement` varchar(255) DEFAULT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `jwk_sha256` (`jwk_sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `authz` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) DEFAULT NULL,
  `registrationID` bigint(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `combinations` varchar(255) DEFAULT NULL,
  `sequence` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `regId_idx` (`registrationID`) COMMENT 'Common lookup',
  CONSTRAINT `regId_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `certificates` (
  `registrationID` bigint(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `serial` varchar(255) NOT NULL,
  `digest` varchar(255) DEFAULT NULL,
  `der` mediumblob,
  `issued` datetime DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  PRIMARY KEY (`serial`),
  KEY `regId_certificates_idx` (`registrationID`) COMMENT 'Common lookup',
  CONSTRAINT `regId_certificates` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `certificateStatus` (
  `serial` varchar(255) NOT NULL,
  `subscriberApproved` tinyint(1) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `ocspLastUpdated` datetime DEFAULT NULL,
  `revokedDate` datetime DEFAULT NULL,
  `revokedReason` int(11) DEFAULT NULL,
  `lastExpirationNagSent` datetime DEFAULT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `challenges` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `authorizationID` varchar(255) NOT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  `type` varchar(255) NOT NULL,
  `status` varchar(255) NOT NULL,
  `error` mediumblob DEFAULT NULL,
  `validated` datetime DEFAULT NULL,
  `uri` varchar(255) DEFAULT NULL,
  `token` varchar(255) NOT NULL,
  `tls` tinyint(1) DEFAULT NULL,
  `validation` mediumblob,
  `validationRecord` mediumblob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `crls` (
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime NOT NULL,
  `crl` varchar(255) NOT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `deniedCSRs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `names` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ocspResponses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime NOT NULL,
  `response` mediumblob,
  PRIMARY KEY (`id`),
  KEY `SERIAL` (`serial`) COMMENT 'Actual lookup mechanism'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `pending_authz` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) DEFAULT NULL,
  `registrationID` bigint(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `combinations` varchar(255) DEFAULT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `regId_idx` (`registrationID`),
  CONSTRAINT `regId_pending_authz` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `identifierData` (
  `reversedName` varchar(255) NOT NULL,
  `certSHA1` varchar(40) NOT NULL,
  UNIQUE INDEX (certSha1, reversedName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `externalCerts` (
  `sha1` varchar(40) NOT NULL,
  `issuer` text DEFAULT NULL,
  `subject` text DEFAULT NULL,
  `notAfter` datetime DEFAULT NULL,
  `spki` blob DEFAULT NULL,
  `valid` tinyint(1) DEFAULT NULL,
  `ev` tinyint(1) DEFAULT NULL,
  `rawDERCert` blob DEFAULT NULL,
  UNIQUE INDEX (sha1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `pending_authz` DROP FOREIGN KEY `regId_pending_authz`;
ALTER TABLE `certificates` DROP FOREIGN KEY `regId_certificates`;
ALTER TABLE `authz` DROP FOREIGN KEY `regId_authz`;
DROP TABLE `registrations`;
DROP TABLE `authz`;
DROP TABLE `certificates`;
DROP TABLE `certificateStatus`;
DROP TABLE `challenges`;
DROP TABLE `crls`;
DROP TABLE `deniedCSRs`;
DROP TABLE `ocspResponses`;
DROP TABLE `pending_authz`;
DROP TABLE `identifierData`;
DROP TABLE `externalCerts`;
