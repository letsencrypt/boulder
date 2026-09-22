#!/usr/bin/env bash

#
# Note: This script exists to support the integration test at
# test/integration/cert_storage_failed_test.go. Because Vitess doesn’t support
# creating triggers through normal SQL, this script waits for the Vitess
# database to come up and then installs a trigger that simulates an error when
# inserting into the certificates table under a specific condition.
#

set -eu

VT_DB="vt_${MYSQL_DATABASE:-boulder_sa}_0"
SOCK="/vt/vtdataroot/vt_0000000001/mysql.sock"
MYSQL_ARGS=(-uroot -S "$SOCK")
TIMEOUT=120

#
# Helpers
#

exit_msg() {
  echo "$*" >&2
  exit 2
}

table_exists() {
  local result
  result="$(mysql "${MYSQL_ARGS[@]}" -Nse \
    "SELECT 1 FROM information_schema.tables WHERE table_schema='${VT_DB}' AND table_name='certificates' LIMIT 1" \
    || true)"
  [ "$result" = "1" ]
}

# Wait for the certificates table to be created
printf '[install_trigger] waiting for %s.certificates to appear...\n' "$VT_DB"

i=0
while [ "$i" -lt "$TIMEOUT" ]
do
  if table_exists
  then
    break
  fi
  sleep 1
  i=$((i+1))
done

if ! table_exists
then
  exit_msg "[install_trigger] ERROR: ${VT_DB}.certificates not found after ${TIMEOUT}s"
fi

# Install trigger that simulates an error when inserting into the certificates
# table for TestIssuanceCertStorageFailed in /test/integration/cert_storage_failed_test.go.
printf '[install_trigger] installing trigger on %s.certificates\n' "$VT_DB"
mysql "${MYSQL_ARGS[@]}" "$VT_DB" <<'SQL'
DELIMITER $$
DROP TRIGGER IF EXISTS fail_ready $$
CREATE TRIGGER fail_ready
BEFORE INSERT ON certificates
FOR EACH ROW
BEGIN
  DECLARE reversedName1 VARCHAR(255);
  SELECT reversedName INTO reversedName1
    FROM issuedNames
    WHERE serial = NEW.serial
      AND reversedName LIKE 'com.wantserror.%';
  IF reversedName1 IS NOT NULL AND reversedName1 != '' THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'Pretend there was an error inserting into certificates';
  END IF;
END $$
DELIMITER ;
SQL

printf '[install_trigger] done\n'
