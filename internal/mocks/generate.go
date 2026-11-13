// Package mocks holds counterfeiter fakes. Regenerate with `make generate`.
package mocks

//go:generate go tool counterfeiter -generate
//counterfeiter:generate -fake-name=FakeDynamoAPI -o=dynamo_api.mock.go ../dynamo API
//counterfeiter:generate -fake-name=FakeLeaseStore -o=lease_store.mock.go ../lease Store
//counterfeiter:generate -fake-name=FakeProber -o=prober.mock.go ../health Prober
//counterfeiter:generate -fake-name=FakeConntrack -o=conntrack.mock.go ../health Conntrack
//counterfeiter:generate -fake-name=FakeReports -o=reports.mock.go ../health Reports
//counterfeiter:generate -fake-name=FakeConnectionTable -o=connection_table.mock.go ../health ConnectionTable
//counterfeiter:generate -fake-name=FakeBoard -o=board.mock.go ../health Board
//counterfeiter:generate -fake-name=FakeEC2 -o=ec2.mock.go ../handoff EC2
//counterfeiter:generate -fake-name=FakeHandoffLocal -o=handoff_local.mock.go ../handoff Local
//counterfeiter:generate -fake-name=FakeRunner -o=runner.mock.go ../network Runner
//counterfeiter:generate -fake-name=FakeNetworkFence -o=network_fence.mock.go ../network Fence
//counterfeiter:generate -fake-name=FakeFence -o=fence.mock.go ../controller Fence
//counterfeiter:generate -fake-name=FakeHealth -o=health.mock.go ../controller Health
//counterfeiter:generate -fake-name=FakePreparer -o=preparer.mock.go ../controller Preparer
//counterfeiter:generate -fake-name=FakeRecords -o=records.mock.go ../update Records
//counterfeiter:generate -fake-name=FakeUpdateRunner -o=update_runner.mock.go ../update Runner
