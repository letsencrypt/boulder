# Case-sensitive encoding/json package

This repository contains a fork of the `encoding/json` package from Go 1.6,
with changes to make it be case-sensitive when unmarshalling a JSON blob into a
struct. In the future, we also plan to make changes to reject JSON blobs that
contain duplicate keys.
