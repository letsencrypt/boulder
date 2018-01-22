
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE orders (
       id BIGINT(20) NOT NULL AUTO_INCREMENT,
       registrationID BIGINT(20) NOT NULL,
       expires DATETIME NOT NULL,
       csr MEDIUMBLOB NOT NULL,
       error MEDIUMBLOB DEFAULT NULL,
       certificateSerial VARCHAR(255) DEFAULT NULL,
       status VARCHAR(255) NOT NULL,
       PRIMARY KEY(id),
       -- We need an index on regID, status, expires to ensure the
       -- countPendingOrdersByRegID RPC has good performance.
       KEY reg_status_expires (registrationID, status, expires)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE orderToAuthz (
       orderID BIGINT(20) NOT NULL,
       authzID VARCHAR(255) NOT NULL,
       PRIMARY KEY order_authz (orderID, authzID),
       KEY authzID (authzID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE orders;
DROP TABLE orderToAuthz;
