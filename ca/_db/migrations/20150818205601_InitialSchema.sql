
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `serialNumber` (
  `id` int(11) DEFAULT NULL,
  `number` int(11) DEFAULT NULL,
  `lastUpdated` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `serialNumber`
  (`id`,
  `number`,
  `lastUpdated`)
VALUES (1,
  1,
  now()
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `serialNumber`
