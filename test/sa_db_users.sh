#
# Copyright 2015 ISRG.  All rights reserved
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This file defines the default users for the primary database, used by
# all the parts of Boulder except the Certificate Authority module, which
# utilizes its own database.
#

# Create users for each component with the appropriate permissions.

# Storage Authority
print_grant SELECT,INSERT,UPDATE authz sa
print_grant SELECT,INSERT,UPDATE,DELETE pendingAuthorizations sa
print_grant 'SELECT(id,Lockcol)' pendingAuthorizations sa
print_grant SELECT,INSERT certificates sa
print_grant SELECT,INSERT,UPDATE certificateStatus sa
print_grant SELECT,INSERT issuedNames sa
print_grant SELECT,INSERT sctReceipts sa
print_grant SELECT,INSERT deniedCSRs sa
print_grant INSERT ocspResponses sa
print_grant SELECT,INSERT,UPDATE registrations sa
print_grant SELECT,INSERT,UPDATE challenges sa
print_grant SELECT,INSERT fqdnSets sa

# OCSP Responder
print_grant SELECT certificateStatus ocsp_resp
print_grant SELECT ocspResponses ocsp_resp

# OCSP Generator Tool (Updater)
print_grant INSERT ocspResponses ocsp_update
print_grant SELECT certificates ocsp_update
print_grant SELECT,UPDATE certificateStatus ocsp_update
print_grant SELECT sctReceipts ocsp_update

# Revoker Tool
print_grant SELECT registrations revoker
print_grant SELECT certificates revoker
print_grant SELECT,INSERT deniedCSRs revoker

# External Cert Importer
print_grant SELECT,INSERT,UPDATE,DELETE identifierData importer
print_grant SELECT,INSERT,UPDATE,DELETE externalCerts importer

# Expiration mailer
print_grant SELECT certificates mailer
print_grant SELECT,UPDATE certificateStatus mailer

# Cert checker
print_grant SELECT certificates cert_checker

# Name set table backfiller
print_grant SELECT certificates backfiller
print_grant INSERT,SELECT fqdnSets backfiller

# Test setup and teardown
print_grant 'ALL PRIVILEGES' '*' test_setup
