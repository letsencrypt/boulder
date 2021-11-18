for n in `"${BIN}" --list` ; do
  echo -e "- <<: *c\n  dst: /opt/boulder/bin/$n"
done
