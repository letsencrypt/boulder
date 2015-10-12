
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `certificateRequests` (
  `id` varchar(255) NOT NULL,
  `registrationID` bigint(20) NOT NULL,
  `created` datetime NOT NULL,
  `expires` datetime NOT NULL,
  `csr` blob NOT NULL,
  `status` varchar(255) DEFAULT NULL,

  PRIMARY KEY (`id`),
  KEY `regId_certificates_idx` (`registrationID`) COMMENT 'Common lookup',
  CONSTRAINT `regId_certificateRequestss`
    FOREIGN KEY (`registrationID`)
    REFERENCES `registrations` (`id`)
    ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `certificates` ADD COLUMN (
  -- Have to allow null for legacy certs
  `requestID` varchar(255)
);

ALTER TABLE `certificates` ADD CONSTRAINT
  `reqId_certificates`
    FOREIGN KEY (`requestID`)
    REFERENCES `certificateRequests` (`id`)
    ON DELETE NO ACTION ON UPDATE NO ACTION;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `certificateRequests`;
ALTER TABLE `certificates` DROP FOREIGN KEY `reqId_certificates`;
ALTER TABLE `certificates` DROP COLUMN `requestID`;
