
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `ruleList` (
  `host` varchar(255) NOT NULL,
  `type` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`host`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE 'ruleList'
