-- TODO(#5670): Remove this file and the _db-next pointer to it.

-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `fqdnSets_old` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `setHash` binary(32) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `issued` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `serial` (`serial`),
  KEY `setHash_issued_idx` (`setHash`,`issued`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE fqdnSets DROP INDEX IF EXISTS serial, ADD INDEX serial (serial);
ALTER TABLE fqdnSets PARTITION BY RANGE(id) (
    PARTITION p_start VALUES LESS THAN MAXVALUE);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `fqdnSets_old`
