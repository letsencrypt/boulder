
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `issuedNames` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  -- DNS names are restricted to the ASCII character set.
  -- 640 char limit is enforced in policy-authority.go.
  `reversedName` VARCHAR(640) CHARACTER SET ascii NOT NULL,
  `issued` DATETIME NOT NULL,
  `serial` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `reversedName_issued_Idx` (`reversedName`, `issued`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `issuedNames`;
