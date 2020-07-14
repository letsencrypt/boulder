
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `newOrdersRL` (
    `id` BIGINT(20) PRIMARY KEY AUTO_INCREMENT,
    `regID` BIGINT(20) NOT NULL,
    `time` DATETIME NOT NULL,
    `count` INTEGER NOT NULL,
    UNIQUE KEY `regID_time_idx` (`regID`, `time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `newOrdersRL`;
