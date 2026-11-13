package irq

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// interrupts is /proc/interrupts on a two-CPU NAT holding the shared ENI.
const interrupts = `           CPU0       CPU1
 10:     208744     195873     GICv3  27 Level     arch_timer
 58:          0          0   ITS-MSI 524288 Edge      ena-mgmnt@pci:0000:00:05.0
 59:   18376402        117   ITS-MSI 524289 Edge      ens5-Tx-Rx-0
 60:        305   20117385   ITS-MSI 524290 Edge      ens5-Tx-Rx-1
 62:          0          0   ITS-MSI 1048576 Edge      ena-mgmnt@pci:0000:00:06.0
 63:   94123412          0   ITS-MSI 1048577 Edge      ens6-Tx-Rx-0
 64:   88003121          0   ITS-MSI 1048578 Edge      ens6-Tx-Rx-1
IPI0:      41223      39876       Rescheduling interrupts
ERR:          0
`

func TestPlan(t *testing.T) {
	{
		// Each interface's queue n goes to CPU n. The management interrupts
		// and the timer stay where they are.
		assert.Equal(t, []Placement{{59, 0}, {60, 1}, {63, 0}, {64, 1}}, Plan(interrupts, 2))
	}
	{
		// More queues than CPUs wrap around
		assert.Equal(t, []Placement{{59, 0}, {60, 0}, {63, 0}, {64, 0}}, Plan(interrupts, 1))
	}
	{
		assert.Empty(t, Plan("           CPU0\n 10:  5  GICv3  27 Level  arch_timer\n", 2))
	}
}
