# Script to update the list of gTLDs
curl -o data/newgtlds.txt http://data.iana.org/TLD/tlds-alpha-by-domain.txt
echo "ONION" >> data/newgtlds.txt
curl -o data/removedtlds.txt https://raw.githubusercontent.com/pzb/TLDs/master/removed/rmtlds.csv
python scripts/consolidate_tlds.py data/newgtlds.txt data/removedtlds.txt util/gtld_map.go
gofmt -w .
