# Creating a new release

1. Update the version string in `libhoney.go`.
2. Add new release notes to the Changelog.
3. Open a PR with above changes.
4. Once the above PR is merged, tag `main` with the new version, e.g. `v0.1.1`. Push the tags. This will kick off a CI workflow, which will publish a draft GitHub release.
5. Update Release Notes on the new draft GitHub release, and publish that.
