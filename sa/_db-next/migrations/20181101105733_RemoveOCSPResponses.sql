
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE ocspResponses;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `ocspResponses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime NOT NULL,
  `response` mediumblob NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SERIAL` (`serial`) COMMENT 'Actual lookup mechanism'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
