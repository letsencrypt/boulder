--
-- Copyright 2015 ISRG.  All rights reserved
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
--
-- This file defines the table schema, foreign keys and indicies of the
-- Certificate Authority database, which is logically separate from that which
-- is utilized by the Storage Authority and administrator tools.
--


CREATE TABLE `serialNumber` (
  `id` int(11) DEFAULT NULL,
  `number` int(11) DEFAULT NULL,
  `lastUpdated` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `serialNumber`
  (`id`,
  `number`,
  `lastUpdated`)
VALUES
  (1,
  1,
  now() );
