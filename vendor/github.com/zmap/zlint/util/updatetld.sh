#!/bin/bash
set -e

# Script to update the list of gTLDs
curl -o newgtlds.txt http://data.iana.org/TLD/tlds-alpha-by-domain.txt
