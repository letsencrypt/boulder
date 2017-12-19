
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE orderFqdnSets (
  id BIGINT(20) NOT NULL AUTO_INCREMENT,
  setHash BINARY(32) NOT NULL,
  orderID BIGINT(20) NOT NULL,
  registrationID BIGINT(20) NOT NULL,
  expires DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY setHash_expires_idx (setHash,expires),
  CONSTRAINT orderFqdnSets_registrationID_registrations
    FOREIGN KEY (registrationID)
    REFERENCES registrations (id)
    ON DELETE CASCADE,
  CONSTRAINT orderFqdnSets_orderID_orders
    FOREIGN KEY (orderID)
    REFERENCES orders (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `orderFqdnSets`;

