//go:build !windows

package registry_test

import (
	"context"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk/registry"
	"github.com/stretchr/testify/assert"
)

func TestWalk_NonWindows_empty(t *testing.T) {
	cfg := model.Registry{Enabled: true, Paths: []model.RegistryPath{{Hive: "HKLM", Key: `SOFTWARE`}}}
	seq := registry.Walk(context.Background(), nil, cfg)
	var count int
	seq(func(_ model.Entry, err error) bool {
		count++
		assert.NoError(t, err)
		return true
	})
	assert.Zero(t, count)
}
