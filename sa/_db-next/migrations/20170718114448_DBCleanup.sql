
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE externalCerts;

DROP TABLE identifierData;

ALTER TABLE certificateStatus DROP LockCol;

ALTER TABLE certificateStatus DROP subscriberApproved;

START TRANSACTION;
ALTER TABLE certificateStatus ADD id bigint(20) NOT NULL;
ALTER TABLE certificateStatus DROP PRIMARY KEY, ADD PRIMARY KEY(id), ADD INDEX serial (serial);
ALTER TABLE certificateStatus MODIFY COLUMN id int NOT NULL AUTO_INCREMENT;
COMMIT;

START TRANSACTION;
ALTER TABLE certificates ADD id bigint(20) NOT NULL;
ALTER TABLE certificates DROP PRIMARY KEY, ADD PRIMARY KEY(id), ADD INDEX serial (serial);
ALTER TABLE certificates MODIFY COLUMN id int NOT NULL AUTO_INCREMENT;
COMMIT;

ALTER TABLE challenges DROP validated;


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

ALTER TABLE certificateStatus ADD LockCol bigint(20) NOT NULL;

ALTER TABLE certificateStatus ADD subscriberApproved tinyint(1) NOT NULL;

START TRANSACTION;
ALTER TABLE certificateStatus DROP PRIMARY KEY, ADD PRIMARY KEY(serial);
ALTER TABLE certificateStatus DROP id;
COMMIT;

START TRANSACTION;
ALTER TABLE certificates DROP PRIMARY KEY, ADD PRIMARY KEY(serial);
ALTER TABLE certificates DROP id;
COMMIT;

ALTER TABLE challenges ADD validated DATETIME;
