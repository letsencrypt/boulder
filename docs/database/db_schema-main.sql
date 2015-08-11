--
-- Copyright 2015 ISRG.  All rights reserved
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
--
-- This file defines the table schema, foreign keys and indicies of the
-- primary database, used by all the parts of Boulder except the Certificate
-- Authority module, which utilizes its own database.
--

CREATE TABLE `registrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `jwk` varchar(1024) NOT NULL,
  `recoveryToken` varchar(255) DEFAULT NULL,
  `contact` varchar(255) DEFAULT NULL,
  `agreement` varchar(255) DEFAULT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_registrations_jwk` (`jwk`(255)) COMMENT 'Used by GetRegistrationByKey'
) ENGINE=InnoDB AUTO_INCREMENT=70 DEFAULT CHARSET=utf8;

CREATE TABLE `authz` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) DEFAULT NULL,
  `registrationID` bigint(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `challenges` varchar(1536) DEFAULT NULL,
  `combinations` varchar(255) DEFAULT NULL,
  `sequence` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `regId_idx` (`registrationID`),
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
  KEY `regId_certificates_idx` (`registrationID`),
  CONSTRAINT `regId_certificates` FOREIGN KEY (`registrationID`) REFERENCES `registrations` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `certificateStatus` (
  `serial` varchar(255) NOT NULL,
  `subscriberApproved` tinyint(1) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `ocspLastUpdated` datetime DEFAULT NULL,
  `revokedDate` datetime DEFAULT NULL,
  `revokedReason` int(11) DEFAULT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `crls` (
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime DEFAULT NULL,
  `crl` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `deniedCSRs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `names` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ocspResponses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime DEFAULT NULL,
  `response` mediumblob,
  PRIMARY KEY (`id`),
  KEY `SERIAL` (`serial`) COMMENT 'Actual lookup mechanism'
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8;

CREATE TABLE `pending_authz` (
  `id` varchar(255) NOT NULL,
  `identifier` varchar(255) DEFAULT NULL,
  `registrationID` bigint(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `challenges` varchar(1536) DEFAULT NULL,
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
