# Contributing to natpair

Thanks for helping. Open an issue before you start on a large change, so we can
agree on the approach first.

## Requirements

- Go, at the version in `go.mod`
- Docker, for `make test-privileged` and `make test-campaign`
- [golangci-lint](https://golangci-lint.run/) v2, for `make lint`
- Terraform 1.6 or later, if you change `terraform/` or `examples/`
- [GoReleaser](https://goreleaser.com/) v2, only for `make release-snapshot`

## Build and test

| Command | What it does |
| --- | --- |
| `make generate` | Regenerates the test fakes in `internal/mocks/*.mock.go`. They are not checked in. |
| `make test` | Runs `make generate`, then the unit tests with the race detector. |
| `make test-privileged` | Runs the tests that change iptables, network namespaces and BPF objects, inside a disposable privileged Docker container. |
| `make test-campaign` | Runs the fault campaign: two real NATs with conntrackd in one privileged container. Set `CASES="a,b"` to run only some cases. Results go to `campaign-results/`. |
| `make lint` | Runs golangci-lint. Run `make generate` first so the tests compile. |
| `make build` | Builds static linux arm64 and amd64 binaries into `bin/`. |
| `make release-snapshot` | Builds the release tarballs into `dist/` without publishing them. |

CI runs `make test`, `make test-privileged`, golangci-lint with and without the
`privileged,campaign,localfixture` build tags, `make build`, and `terraform fmt`
and `validate` for the module and each example.

## Compatibility

Running pairs mix releases during an upgrade, and users apply new module
versions to existing pairs. Keep these compatible with what is already
deployed:

- the lease protocol and the lease table's records
- the config file the NATs read (`deploy/config.example.json`)
- the Terraform module's resource names and addresses. Renaming one replaces
  the resource, so add a `moved` block if you must rename.

If a change can't stay compatible, say so in the pull request and describe the
upgrade path.

## Pull requests

Use a [Conventional Commits](https://www.conventionalcommits.org/) title, such
as `feat: ...`, `fix: ...`, `docs: ...`, `test: ...` or `chore: ...`. The
release notes group changes by these types and leave out `docs`, `test` and
`chore`.

Describe what changed, why, and how you tested it.

## Releases

Maintainers release by pushing a `vX.Y.Z` tag on `master`. The release workflow
then builds the tarballs with GoReleaser, publishes them with `checksums.txt` as
a GitHub release, and attests their build provenance.
