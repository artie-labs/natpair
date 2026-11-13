//go:build !linux

package pacing

import (
	"context"
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("pacing requires Linux")

type kernel struct{}

func newKernel(string, []netip.Prefix) *kernel { return &kernel{} }

func (k *kernel) load() error                                 { return errUnsupported }
func (k *kernel) attach(context.Context, string) error        { return errUnsupported }
func (k *kernel) remove(context.Context) error                { return nil }
func (k *kernel) setLimits(Limits) error                      { return errUnsupported }
func (k *kernel) allowances(string) (Allowances, bool, error) { return Allowances{}, false, nil }
func (k *kernel) close()                                      {}
func (k *kernel) forget(string)                               {}
func (k *kernel) readTotals() (Totals, error)                 { return Totals{}, errUnsupported }

func (k *kernel) readWorkers() (map[[4]byte]Counters, error) {
	return nil, errUnsupported
}
