//go:build !windows

package registry

import (
	"context"
	"iter"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
)

// Walk returns an empty iterator on non-Windows platforms.
func Walk(_ context.Context, _ *stats.Stats, cfg model.Registry) iter.Seq2[model.Entry, error] {
	return func(yield func(model.Entry, error) bool) {}
}
