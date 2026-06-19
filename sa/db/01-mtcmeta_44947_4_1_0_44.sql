USE mtcmeta_44947_4_1_0_44;

-- latestCheckpoint is a single-row table pointing to the id of the latest checkpoints.
-- Its single row is locked with SELECT ... FOR UPDATE before signing happens, and then
-- updated after signing happens.
CREATE TABLE `latestCheckpoint` (
    `id` bigint(20) NOT NULL,
    -- ASCII-format OID relative to 1.3.6.1.4.1
    `mtcLogID` varchar(255) NOT NULL
);

CREATE TABLE `checkpoints` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    -- ASCII-format OID relative to 1.3.6.1.4.1
    -- https://tlswg.org/tls-trust-anchor-ids/draft-ietf-tls-trust-anchor-ids.html#name-trust-anchor-identifiers
    -- https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
    -- This is redundant with the database/keyspace name and will be used for extra checks to ensure
    -- configuration errors can't result in using the wrong database/keyspace.
    `mtcLogID` varchar(255) NOT NULL,
    `mtcaSignature` mediumblob,
    -- For simplicity we start out with a hardcoded assumption of one mirror signature,
    -- the planned CQRP requirement. If requirements increase we can add more fields.
    -- `mirrorID` is an ASCII-format OID relative to 1.3.6.1.4.1.
    -- Note: these two fields start empty and are filled later.
    `mirrorID` varchar(255),
    `mirrorSignature` mediumblob,

    -- Signed-over data: https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
    -- Note that `log_origin` and `cosigner_name` in the link above are derived from `mtcLogID` and `mirrorID` respectively.
    -- Also, for checkpoint signatures start == 0 and end == tree size.
    -- `treeSize` will be strictly increasing over time, enforced by the application.
    -- Appending to this table will involve a check (in a transaction) that the treeSize and root hash of the
    -- highest-sized checkpoint match what the CA expects.
    `treeSize` bigint(20) unsigned NOT NULL,
    `rootHash` binary(32) NOT NULL,

    `created` datetime DEFAULT current_timestamp(),
    PRIMARY KEY (`id`),
    KEY `mtcLogID_treeSize` (`mtcLogID`, `treeSize`)
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

