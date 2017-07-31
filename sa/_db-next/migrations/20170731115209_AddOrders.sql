
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE orders (
       id bigint(20) NOT NULL AUTO_INCREMENT,
       registrationID bigint(20) NOT NULL,
       expires datetime NOT NULL,
       csr mediumblob NOT NULL,
       error blob DEFAULT NULL,
       certificateSerial varchar(255) DEFAULT NULL,
       PRIMARY KEY(id),
       KEY reg_expires (registrationID, expires)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE orderToAuthz (
       orderID bigint(20) NOT NULL,
       authzID varchar(255) NOT NULL,
       PRIMARY KEY order_authz (orderID, authzID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE orders;
DROP TABLE orderToAuthz;
