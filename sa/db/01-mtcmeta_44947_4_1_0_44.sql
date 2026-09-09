-- This schema is written to work either in a DB-per-issuance-log configuration (current MariaDB),
-- or optionally as a Vitess sharded keyspace where each issuance log is in a separate shard.
USE mtcmeta_44947_4_1_0_44;

-- latestCheckpoint contains the latest checkpoint for a specific MTC log ID.
--
-- In MariaDB, it will only ever contain a single row. In Vitess it could contain a row
-- per mtcLogID and be sharded on mtcLogID. To ensure the "single row per MTC log ID"
-- property, we make mtcLogID a primary key.
--
-- The row for a given mtcLogID is locked with SELECT ... FOR UPDATE before signing
-- happens, and then updated after signing happens.
CREATE TABLE `latestCheckpoint` (
    -- ASCII-format OID relative to 1.3.6.1.4.1
    `mtcLogID` varchar(255) NOT NULL,
    -- ID of a checkpoint in the `checkpoints` table.
    `id` bigint(20) NOT NULL,
    PRIMARY KEY (`mtcLogID`)
);

CREATE TABLE `checkpoints` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    -- ASCII-format OID relative to 1.3.6.1.4.1
    -- https://tlswg.org/tls-trust-anchor-ids/draft-ietf-tls-trust-anchor-ids.html#name-trust-anchor-identifiers
    -- https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
    -- This is redundant with the database/keyspace name and will be used for extra checks to ensure
    -- configuration errors can't result in using the wrong database/keyspace.
    `mtcLogID` varchar(255) NOT NULL,
    -- An ML-DSA-44 signature over a CosignedMessage with `timestamp` and `start` both zero.
    -- TODO(#8991): Change this to store a signed note signature line instead, since that format can
    -- carry a nonzero `timestamp`.
    `mtcaSignature` mediumblob,

    -- For simplicity we start out with a hardcoded assumption of one mirror signature,
    -- the planned CQRP requirement. If requirements increase we can add more fields.
    -- `mirrorID` is an ASCII-format OID relative to 1.3.6.1.4.1.
    -- Note: these two fields start empty and are filled later.
    `mirrorID` varchar(255),
    -- An ML-DSA-44 signature over a CosignedMessage with `timestamp` and `start` both zero.
    -- TODO(#8991): Change this to store a signed note signature line instead, since that format can
    -- carry a nonzero `timestamp`.
    `mirrorSignature` mediumblob,

    -- Signed-over data: https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
    -- Note that `log_origin` and `cosigner_name` in the link above are derived from `mtcLogID` and `mirrorID` respectively.
    -- Also, for checkpoint signatures start == 0 and end == tree size.
    -- `treeSize` will be strictly increasing over time, enforced by the application.
    `treeSize` bigint(20) unsigned NOT NULL,
    `rootHash` binary(32) NOT NULL,

    -- The IDs of the one or two subtrees in the `checkpointSubtrees` table implied by the delta between
    -- this checkpoint and the previous one. These two subtrees must cover all entries between this checkpoint
    -- and the previous one.
    -- The first checkpoint of an issuance log will have these both NULL. Subsequent checkpoints will have `subtreeID2` NULL
    -- if a single subtree covers the delta.
    `subtreeID1` bigint(20) unsigned,
    `subtreeID2` bigint(20) unsigned,

    `created` datetime DEFAULT current_timestamp(),
    PRIMARY KEY (`id`),
    KEY `mtcLogID_treeSize` (`mtcLogID`, `treeSize`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- Represents the pair-of-subtrees signed every checkpoint, to put into standalone certificates.
-- The subtrees used for landmark-relative certificates are not represented explicitly
-- in the database.
--
-- Note: standalone certificates are assigned to a specific checkpoint subtree at issuance.
-- We don't look these up dynamically by serial number, so we don't have indexes on
-- `subtreeStart` or `subtreeEnd`. Note that if we do later add an index, we'd have to pick
-- either `subtreeStart` or `subtreeEnd`, since indexes are hierarchical. An index on
-- (`subtreeStart`, `subtreeEnd`) isn't better than an index on (`subtreeEnd`) for answering
-- the question "which checkpoint subtrees include N?".
CREATE TABLE `checkpointSubtrees` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    -- ASCII-format OID relative to 1.3.6.1.4.1
    -- https://tlswg.org/tls-trust-anchor-ids/draft-ietf-tls-trust-anchor-ids.html#name-trust-anchor-identifiers
    -- https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
    -- This is redundant with the database/keyspace name and will be used for extra checks to ensure
    -- configuration errors can't result in using the wrong database/keyspace.
    `mtcLogID` varchar(255) NOT NULL,
    -- An ML-DSA-44 signature over a CosignedMessage with zero timestamp.
    `mtcaSignature` mediumblob NOT NULL,

    -- `mirrorID` is an ASCII-format OID relative to 1.3.6.1.4.1.
    -- Note: these two fields start empty and are filled later.
    `mirrorID` varchar(255),
    -- An ML-DSA-44 signature over a CosignedMessage with zero timestamp.
    `mirrorSignature` mediumblob,

    -- Signed-over data: https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
    -- Note that `log_origin` and `cosigner_name` in the link above are derived from `mtcaID` and `mirrorID` respectively.
    `subtreeStart` bigint(20) unsigned NOT NULL,
    `subtreeEnd` bigint(20) unsigned NOT NULL,
    `subtreeHash` binary(32) NOT NULL,

    `created` datetime DEFAULT current_timestamp(),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;


CREATE TABLE `landmarks` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    -- ASCII-format OID relative to 1.3.6.1.4.1
    `mtcLogID` varchar(255) NOT NULL,
    -- Each newly added landmark must have a strictly larger landmarkNumber
    -- than the previous one. We'll enforce this at the application level,
    -- not the database level.
    `landmarkNumber` bigint(20) unsigned NOT NULL,
    `treeSize` bigint(20) unsigned NOT NULL,
    `created` datetime DEFAULT current_timestamp(),
    PRIMARY KEY (`id`),
    KEY `mtcLogID_landmarkNumber` (`mtcLogID`, `landmarkNumber`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

