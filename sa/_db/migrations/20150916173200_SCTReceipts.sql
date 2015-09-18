
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `sctReceipts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `sctVersion` tinyint(1) NOT NULL,
  `logID` varchar(255) NOT NULL,
  `timestamp` bigint(20) NOT NULL,
  `extensions` blob,
  `signature` blob,
  `certificateSerial` varchar(255) NOT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `certificateSerial_logID` (`certificateSerial`, `logID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `sctReceipts`;
