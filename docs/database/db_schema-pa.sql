--
-- Copyright 2015 ISRG.  All rights reserved
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
--
-- This file defines the table schema, foreign keys and indicies of the
-- Policy Authority database, which is logically separate from that which
-- is utilized by the Storage Authority and administrator tools.
--

CREATE TABLE `ruleList` (
  `host` varchar(255) NOT NULL,
  `type` char(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
