USE incidents_sa;

CREATE TABLE `incident_foo` (
    `serial` varchar(255) NOT NULL,
    `registrationID` bigint(20) unsigned NULL,
    `orderID` bigint(20) unsigned NULL,
    `lastNoticeSent` datetime NULL,
    PRIMARY KEY (`serial`),
    KEY `registrationID_idx` (`registrationID`),
    KEY `orderID_idx` (`orderID`)
) CHARSET=utf8mb4;

CREATE TABLE `incident_bar` (
    `serial` varchar(255) NOT NULL,
    `registrationID` bigint(20) unsigned NULL,
    `orderID` bigint(20) unsigned NULL,
    `lastNoticeSent` datetime NULL,
    PRIMARY KEY (`serial`),
    KEY `registrationID_idx` (`registrationID`),
    KEY `orderID_idx` (`orderID`)
) CHARSET=utf8mb4;
