
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `issuedNames` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `reversedName` VARCHAR(1024) NOT NULL,
  `issued` DATETIME NOT NULL,
  `serial` VARCHAR(255) NOT NULL,
  `LockCol` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `reversedName_issued_Idx` (`reversedName`, `issued`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `issuedNames`;
