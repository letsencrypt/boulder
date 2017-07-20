
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- externalCerts and identifierData were originally needed for PoP challenges
-- but were never used and can safely be removed since PoP challenges were
-- removed from the spec.
DROP TABLE externalCerts;

DROP TABLE identifierData;

ALTER TABLE certificateStatus DROP LockCol,
	DROP subscriberApproved;

START TRANSACTION;
ALTER TABLE certificateStatus DROP PRIMARY KEY,
	ADD id BIGINT(20) NOT NULL AUTO_INCREMENT FIRST,
	ADD PRIMARY KEY(id),
	ADD UNIQUE serial (serial);
COMMIT;

START TRANSACTION;
ALTER TABLE certificates DROP PRIMARY KEY,
	ADD id BIGINT(20) NOT NULL AUTO_INCREMENT FIRST,
	ADD PRIMARY KEY(id),
	ADD UNIQUE serial (serial);
COMMIT;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
CREATE TABLE `externalCerts` (
  `sha1` varchar(40) NOT NULL,
  `issuer` text,
  `subject` text,
  `notAfter` datetime DEFAULT NULL,
  `spki` blob,
  `valid` tinyint(1) DEFAULT NULL,
  `ev` tinyint(1) DEFAULT NULL,
  `rawDERCert` blob,
  UNIQUE KEY `sha1` (`sha1`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `identifierData` (
  `reversedName` varchar(255) NOT NULL,
  `certSHA1` varchar(40) NOT NULL,
  UNIQUE KEY `certSHA1` (`certSHA1`,`reversedName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE certificateStatus ADD LockCol BIGINT(20) NOT NULL,
	ADD subscriberApproved TINYINT(1) NOT NULL;

START TRANSACTION;
ALTER TABLE certificateStatus DROP PRIMARY KEY,
	DROP KEY (serial),
	ADD PRIMARY KEY(serial),
	DROP id;
COMMIT;

START TRANSACTION;
ALTER TABLE certificates DROP PRIMARY KEY,
	DROP KEY serial,
	ADD PRIMARY KEY(serial),
	DROP id;
COMMIT;
