-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP TABLE `deniedCSRs`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `deniedCSRs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `names` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
