
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE `crls`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `crls` (
  `serial` varchar(255) NOT NULL,
  `createdAt` datetime NOT NULL,
  `crl` varchar(255) NOT NULL,
  PRIMARY KEY (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

