package model_test

import (
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/stretchr/testify/require"
)

func TestRegistryConfigCUEValidation(t *testing.T) {
	cfg, err := model.LoadConfig(strings.NewReader(`
version: 0
service:
  mode: manual
registry:
  enabled: true
  paths:
    - hive: HKLM
      key: "SOFTWARE\\Vendor\\App"
  max_depth: 3
  max_value_size: 1048576
  wow64: true
  include:
    keys: ["Certs"]
    values: ["(?i)cert"]
  exclude:
    keys: []
    values: []
`))
	require.NoError(t, err)
	require.True(t, cfg.Registry.Enabled)
	require.Equal(t, "HKLM", cfg.Registry.Paths[0].Hive)
	require.Equal(t, 3, cfg.Registry.MaxDepth)
}

func TestRegistryConfigDefaults(t *testing.T) {
	cfg, err := model.LoadConfig(strings.NewReader(`
version: 0
service:
  mode: manual
`))
	require.NoError(t, err)
	require.False(t, cfg.Registry.Enabled)
	require.Equal(t, 1048576, cfg.Registry.MaxValueSize)
}

func TestRegistryConfigInvalidHive(t *testing.T) {
	_, err := model.LoadConfig(strings.NewReader(`
version: 0
service:
  mode: manual
registry:
  enabled: true
  paths:
    - hive: INVALID
      key: "SOFTWARE"
`))
	require.Error(t, err)
}
