
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE `challenges`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `challenges` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `authorizationID` varchar(255) NOT NULL,
  `LockCol` bigint(20) DEFAULT NULL,
  `type` varchar(255) NOT NULL,
  `status` varchar(255) NOT NULL,
  `error` mediumblob DEFAULT NULL,
  `validated` datetime DEFAULT NULL,
  `token` varchar(255) NOT NULL,
  `validationRecord` mediumblob DEFAULT NULL,
  `keyAuthorization` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `authorizationID_challenges_idx` (`authorizationID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
