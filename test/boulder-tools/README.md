# Boulder-Tools Docker Image Utilities

In CI and our development environment we do not rely on the Go environment of
the host machine, and instead use Go installed in a container. To simplify
things we separate all of Boulder's build dependencies into its own
`boulder-tools` Docker image.

## Go Versions

Rather than install multiple versions of Go within the same `boulder-tools`
container we maintain separate images for each Go version we support.

When a new Go version is available we perform serveral steps to integrate it to our workflow:

1. We add it to the `GO_VERSIONS` array in `tag_and_upload.sh`.
2. We run the `tag_and_upload.sh` script to build, tag, and upload
   a `boulder-tools` image for each of the `GO_VERSIONS`
3. We update `.travis.yml`, duplicating the existing build tasks, adding new
   `GO_VERSION=` `ENV` entries for the new Go version.

After some time when we have spot checked the new Go release and coordinated
a staging/prod environment upgrade with the operations team we can remove the
old `GO_VERSIONS` entries and delete their respective build matrix items.
