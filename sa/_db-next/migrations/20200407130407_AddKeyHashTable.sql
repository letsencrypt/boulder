
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `keyHashToSerial` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `keyHash` binary(32) NOT NULL,
  `certNotAfter` datetime NOT NULL,
  `certSerial` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `keyHash_certNotAfter` (`keyHash`, `certNotAfter`),
  UNIQUE KEY `unique_keyHash_certserial` (`keyHash`, `certSerial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `keyHashToSerial`;
