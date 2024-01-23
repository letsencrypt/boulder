-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `replacementOrders` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) NOT NULL,
  `orderId` bigint(20) DEFAULT NULL,
  `orderExpires` datetime DEFAULT NULL,
  `replaced` boolean DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `serial_id_idx` (`serial`, `id`),
  KEY `orderId_idx` (`orderId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
 PARTITION BY RANGE(id)
(PARTITION p_start VALUES LESS THAN (MAXVALUE));

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `replacementOrders`;
