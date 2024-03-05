-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE `orders`;
CREATE TABLE `orders` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `expires` datetime NOT NULL,
  `error` mediumblob DEFAULT NULL,
  `certificateSerial` varchar(255) DEFAULT NULL,
  `beganProcessing` tinyint(1) NOT NULL DEFAULT 0,
  `created` datetime NOT NULL,
  `certificateProfileName` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `reg_status_expires` (`registrationID`,`expires`),
  KEY `regID_created_idx` (`registrationID`,`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
 PARTITION BY RANGE(id)
(PARTITION p_start VALUES LESS THAN (MAXVALUE));

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `orders`;
CREATE TABLE `orders` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `registrationID` bigint(20) NOT NULL,
  `expires` datetime NOT NULL,
  `error` mediumblob DEFAULT NULL,
  `certificateSerial` varchar(255) DEFAULT NULL,
  `beganProcessing` tinyint(1) NOT NULL DEFAULT 0,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `reg_status_expires` (`registrationID`,`expires`),
  KEY `regID_created_idx` (`registrationID`,`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
 PARTITION BY RANGE(id)
(PARTITION p_start VALUES LESS THAN (MAXVALUE));
