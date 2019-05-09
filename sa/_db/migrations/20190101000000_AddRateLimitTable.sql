-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `certificatesPerName` (
    `id` BIGINT(20) PRIMARY KEY AUTO_INCREMENT,
    `eTLDPlusOne` VARCHAR(255) NOT NULL,
    `time` DATETIME NOT NULL,
    `count` INTEGER NOT NULL,
    UNIQUE KEY `eTLDPlusOne_time_idx` (`eTLDPlusOne`, `time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `certificatesPerName`;
