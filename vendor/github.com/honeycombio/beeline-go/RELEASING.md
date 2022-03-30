# Releasing

- Update the version in `version.go` to the new version
- Update `CHANGELOG.md` with changes since last release
- Commit changes, push, and open a release preparation pull request for review
- Once the pull request is merged, fetch the updated `main` branch
- Apply a tag for the new version on the merged commit: vX.Y.Z, for example v1.1.2
- Push the new version tag up to the project repository to kick off build and artifact publishing to GitHub