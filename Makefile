.PHONY: generate
generate:
	rm -f internal/mocks/*.mock.go && cd internal/mocks && go tool counterfeiter -generate

# Static binaries for arm64 and amd64 Amazon Linux 2023 NATs.
.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/natpair-linux-arm64 ./cmd/natpair
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/natpair-linux-amd64 ./cmd/natpair

# Builds the release tarballs into dist/ without publishing anything.
.PHONY: release-snapshot
release-snapshot:
	goreleaser release --snapshot --clean

.PHONY: test
test: generate
	go test -race ./...

# Tests that change iptables, network namespaces and BPF objects. They run in a
# disposable privileged container so they never touch the host's networking.
.PHONY: test-privileged
test-privileged: generate
	docker build -q -t natpair-test -f test.Dockerfile .
	docker run --rm --privileged -v "$(CURDIR):/src" -v natpair-go-cache:/root/.cache -v natpair-go-mod:/go/pkg/mod \
		natpair-test go test -tags privileged ./...

# Fault campaign: two real NATs, conntrackd and the kernel deadline inside one
# disposable privileged container, with each NAT in its own network and mount
# namespaces. Results and logs go to campaign-results/. CASES="a,b" runs only
# the named cases.
.PHONY: test-campaign
test-campaign: generate
	docker build -q -t natpair-test -f test.Dockerfile .
	docker run --rm --privileged -v "$(CURDIR):/src" -v natpair-go-cache:/root/.cache -v natpair-go-mod:/go/pkg/mod \
		natpair-test go test -tags campaign -timeout 20m -v -count=1 ./test/campaign/ -args -out /src/campaign-results -cases "$(CASES)"

.PHONY: lint
lint:
	golangci-lint run
