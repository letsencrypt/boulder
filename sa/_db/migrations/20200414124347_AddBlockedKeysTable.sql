
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `blockedKeys` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    `keyHash` binary(32) NOT NULL UNIQUE,
    `added` datetime NOT NULL,
    `source` tinyint NOT NULL,
    `comment` varchar(255) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `blockedKeys`;
