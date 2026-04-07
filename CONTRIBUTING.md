# Contributing

Contributions are welcome through issues and pull requests.

## License

By submitting a contribution to this repository, you agree that your contribution is licensed under the repository's MIT license.

## Scope

Please keep pull requests focused and describe any user-visible behavior changes clearly.

## Releases

Run `./scripts/prepare_vsr_release.sh <version>` from a clean checkout when preparing a CLI release. It updates the shared workspace version, refreshes `Cargo.lock`, runs the publish-time package checks, creates the release commit, and creates the matching `vsra-v<version>` tag together so the tag cannot point at a pre-bump commit.
