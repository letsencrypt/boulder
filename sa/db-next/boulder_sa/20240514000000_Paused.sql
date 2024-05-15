-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `paused` (
  `registrationID` bigint(20) NOT NULL,
  `identifierType` tinyint(4) NOT NULL,
  `identifierValue` varchar(255) NOT NULL,
  `pausedAt` datetime DEFAULT NULL,
  `unpausedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`registrationID`, `identifierType`, `identifierValue`)
);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `paused`;
