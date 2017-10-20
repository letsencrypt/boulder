
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE orders DROP COLUMN csr;

CREATE TABLE requestedNames (
  `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `orderID` BIGINT(20) NOT NULL,
  -- 253 is the maximum allowed DNS name length
  -- We use ASCII explicitly here since there is no expectation that un-punycode
  -- encoded unicode names will be stored
  `reversedName` varchar(253) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY(id),
  KEY `orderID_idx` (`orderID`),
  KEY `reversedName_idx` (`reversedName`),
  CONSTRAINT `orderID_orders` FOREIGN KEY (`orderID`) REFERENCES `orders` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE orders ADD COLUMN csr MEDIUMBLOB NOT NULL;
DROP TABLE requestedNames;
