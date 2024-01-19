-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `replacementOrders` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `newOrderId` bigint(20) DEFAULT NULL,
  `oldCertSerial` varchar(255) NOT NULL,
  `finalizedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `oldCertSerial_id_idx` (`oldCertSerial`, `id`),
  KEY `newOrderId_idx` (`newOrderId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
 PARTITION BY RANGE(id)
(PARTITION p_start VALUES LESS THAN (MAXVALUE));

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `replacementOrders`;
