
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `blacklist` (
  `host` varchar(255) NOT NULL,
  PRIMARY KEY (`host`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `whitelist` (
  `host` varchar(255) NOT NULL,
  PRIMARY KEY (`host`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE 'blacklist';
DROP TABLE 'whitelist';
