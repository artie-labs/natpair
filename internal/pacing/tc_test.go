package pacing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttachScript(t *testing.T) {
	{
		// An ENA interface with two transmit queues gets one sch_fq per queue
		assert.Equal(t, `qdisc replace dev ens6 root handle 7a01: mq
qdisc replace dev ens6 parent 7a01:1 fq limit 100000 flow_limit 10000
qdisc replace dev ens6 parent 7a01:2 fq limit 100000 flow_limit 10000
qdisc replace dev ens6 clsact
filter replace dev ens6 ingress protocol all pref 7001 handle 1 bpf direct-action object-pinned /sys/fs/bpf/natpair/pacing/mark
filter replace dev ens6 egress protocol all pref 7001 handle 1 bpf direct-action object-pinned /sys/fs/bpf/natpair/pacing/pace
`, attachScript("ens6", 2, "/sys/fs/bpf/natpair/pacing/mark", "/sys/fs/bpf/natpair/pacing/pace"))
	}
	{
		// mq needs several queues, so a single-queue interface gets sch_fq at
		// the root. Queue numbers are hexadecimal, as tc reads them.
		assert.Equal(t, `qdisc replace dev lan root handle 7a01: fq limit 100000 flow_limit 10000
qdisc replace dev lan clsact
filter replace dev lan ingress protocol all pref 7001 handle 1 bpf direct-action object-pinned m
filter replace dev lan egress protocol all pref 7001 handle 1 bpf direct-action object-pinned p
`, attachScript("lan", 1, "m", "p"))
		assert.Contains(t, attachScript("ens5", 16, "m", "p"), "parent 7a01:10 fq")
	}
}

func TestDetachScript(t *testing.T) {
	parse := func(output string) []qdisc {
		qdiscs, err := parseTC[qdisc](output)
		require.NoError(t, err)
		return qdiscs
	}
	// Output of `tc -j qdisc show` after attachScript on a two-queue interface.
	attached := parse(`[{"kind":"mq","handle":"7a01:","root":true,"options":{}},{"kind":"fq","handle":"8002:","parent":"7a01:2","options":{}},{"kind":"fq","handle":"8001:","parent":"7a01:1","options":{}},{"kind":"clsact","handle":"ffff:","parent":"ffff:fff1","options":{}}]`)
	filters, err := parseTC[filter](`[{"protocol":"all","pref":7001,"kind":"bpf","chain":0},{"protocol":"all","pref":7001,"kind":"bpf","chain":0,"options":{"handle":"0x1","bpf_name":"natpair_pace","direct-action":true}}]`)
	require.NoError(t, err)
	{
		assert.Equal(t, `filter del dev ens6 ingress pref 7001
filter del dev ens6 egress pref 7001
qdisc del dev ens6 clsact
qdisc del dev ens6 root
`, detachScript("ens6", attached, filters, filters))
	}
	{
		// Another tool's filter keeps the clsact qdisc
		other := append([]filter{{Pref: 49152}}, filters...)
		assert.Equal(t, `filter del dev ens6 ingress pref 7001
filter del dev ens6 egress pref 7001
qdisc del dev ens6 root
`, detachScript("ens6", attached, other, filters))
	}
	{
		// A root qdisc natpair didn't install stays, as does a clsact qdisc
		// without natpair's filters
		defaults := parse(`[{"kind":"mq","handle":"0:","root":true,"options":{}},{"kind":"fq_codel","handle":"0:","parent":":1","options":{}},{"kind":"clsact","handle":"ffff:","parent":"ffff:fff1","options":{}}]`)
		assert.Empty(t, detachScript("ens5", defaults, nil, nil))
	}
	{
		// A half-finished attach, with only the root qdisc in place
		assert.Equal(t, "qdisc del dev lan root\n", detachScript("lan", parse(`[{"kind":"fq","handle":"7a01:","root":true,"options":{}}]`), nil, nil))
	}
	{
		// tc prints nothing for some empty results
		assert.Empty(t, parse(""))
		_, err := parseTC[qdisc]("Cannot find device")
		assert.ErrorContains(t, err, "failed to parse tc output")
	}
}
