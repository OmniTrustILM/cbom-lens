package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	tests := []struct {
		name        string
		config      model.CBOM
		wantVersion cdx.SpecVersion
		wantSchema  string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid version 1.6",
			config:      model.CBOM{Version: "1.6"},
			wantVersion: cdx.SpecVersion1_6,
			wantSchema:  "https://cyclonedx.org/schema/bom-1.6.schema.json",
			wantErr:     false,
		},
		{
			name:    "unsupported version",
			config:  model.CBOM{Version: "2.0"},
			wantErr: true,
			errMsg:  "unsupported cbom spec version 2.0",
		},
		{
			name:    "empty version",
			config:  model.CBOM{Version: ""},
			wantErr: true,
			errMsg:  "unsupported cbom spec version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				require.Nil(t, builder)
			} else {
				require.NoError(t, err)
				require.NotNil(t, builder)
				require.Equal(t, tt.wantVersion, builder.version)
				require.Equal(t, tt.wantSchema, builder.schema)
				require.NotNil(t, builder.components)
				require.NotNil(t, builder.dependencies)
				require.NotNil(t, builder.properties)
				require.Empty(t, builder.components)
				require.Empty(t, builder.dependencies)
			}
		})
	}
}

func TestBuilder_WithCounter(t *testing.T) {
	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	require.Nil(t, builder.counter)

	counter := stats.New(t.Name())
	result := builder.WithCounter(counter)

	require.Equal(t, builder, result) // Check fluent interface
	require.Equal(t, counter, builder.counter)
}

func TestBuilder_AppendDetections(t *testing.T) {
	ctx := context.Background()

	t.Run("single detection with components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Location: "/test/path",
			Components: []cdx.Component{
				{
					BOMRef: "comp-1",
					Name:   "test-component",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Len(t, builder.components, 1)
		require.Contains(t, builder.components, "comp-1")
		require.Equal(t, "test-component", builder.components["comp-1"].Name)
	})

	t.Run("multiple detections", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detections := []model.Detection{
			{
				Location: "/path1",
				Components: []cdx.Component{
					{BOMRef: "comp-1", Name: "component-1", Type: cdx.ComponentTypeLibrary},
				},
			},
			{
				Location: "/path2",
				Components: []cdx.Component{
					{BOMRef: "comp-2", Name: "component-2", Type: cdx.ComponentTypeLibrary},
				},
			},
		}

		builder.AppendDetections(ctx, detections...)

		require.Len(t, builder.components, 2)
		require.Contains(t, builder.components, "comp-1")
		require.Contains(t, builder.components, "comp-2")
	})

	t.Run("detection with dependencies", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1", "dep-2"}
		detection := model.Detection{
			Dependencies: []cdx.Dependency{
				{
					Ref:          "comp-1",
					Dependencies: &deps,
				},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Len(t, builder.dependencies, 1)
		require.Contains(t, builder.dependencies, "comp-1")
		require.Equal(t, &deps, builder.dependencies["comp-1"])
	})

	t.Run("ignore component without BOMRef", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Components: []cdx.Component{
				{Name: "component-without-ref", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.components)
	})

	t.Run("ignore component without Name", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Components: []cdx.Component{
				{BOMRef: "comp-1", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.components)
	})

	t.Run("ignore dependency without Ref", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1"}
		detection := model.Detection{
			Dependencies: []cdx.Dependency{
				{Dependencies: &deps},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.dependencies)
	})

	t.Run("duplicate component adds evidence location", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection1 := model.Detection{
			Location: "/path1",
			Components: []cdx.Component{
				{BOMRef: "comp-1", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
		}
		detection2 := model.Detection{
			Location: "/path2",
			Components: []cdx.Component{
				{BOMRef: "comp-1", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection1, detection2)

		require.Len(t, builder.components, 1)
		comp := builder.components["comp-1"]
		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 2)
	})

	t.Run("duplicate dependency is ignored", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1"}
		detection1 := model.Detection{
			Dependencies: []cdx.Dependency{
				{Ref: "comp-1", Dependencies: &deps},
			},
		}
		detection2 := model.Detection{
			Dependencies: []cdx.Dependency{
				{Ref: "comp-1", Dependencies: &deps},
			},
		}

		builder.AppendDetections(ctx, detection1, detection2)

		require.Len(t, builder.dependencies, 1)
	})
}

func TestBuilder_BOM(t *testing.T) {
	t.Run("basic BOM structure", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		bom := builder.BOM(t.Context())

		require.Equal(t, "https://cyclonedx.org/schema/bom-1.6.schema.json", bom.JSONSchema)
		require.Equal(t, "CycloneDX", bom.BOMFormat)
		require.Equal(t, cdx.SpecVersion1_6, bom.SpecVersion)
		require.NotEmpty(t, bom.SerialNumber)
		require.Equal(t, 1, bom.Version)
		require.NotNil(t, bom.Metadata)
		require.NotNil(t, bom.Components)
		require.NotNil(t, bom.Dependencies)
	})

	t.Run("BOM with components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		var components = []cdx.Component{
			{
				BOMRef: "comp-1",
				Name:   "test-component-1",
				Type:   cdx.ComponentTypeLibrary,
			},
			{
				BOMRef: "crypt/library@sha256:this-is-a-hash",
				Name:   "test-component-2",
				Type:   cdx.ComponentTypeLibrary,
			},
		}

		builder.AppendDetections(t.Context(),
			model.Detection{Components: components},
		)

		bom := builder.BOM(t.Context())

		require.Len(t, *bom.Components, 2)

		var uuidSuffix = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
		require.Regexp(t, uuidSuffix, (*bom.Components)[0].BOMRef)
		require.Regexp(t, uuidSuffix, (*bom.Components)[1].BOMRef)
	})

	t.Run("BOM metadata", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		bom := builder.BOM(t.Context())

		require.NotNil(t, bom.Metadata)
		require.NotEmpty(t, bom.Metadata.Timestamp)
		require.NotNil(t, bom.Metadata.Lifecycles)
		require.Len(t, *bom.Metadata.Lifecycles, 1)
		require.EqualValues(t, "operations", (*bom.Metadata.Lifecycles)[0].Phase)
		require.NotNil(t, bom.Metadata.Component)
		require.Equal(t, "CBOM-Lens", bom.Metadata.Component.Name)
		require.Equal(t, "application", string(bom.Metadata.Component.Type))
	})
}

func TestBuilder_AsJSON(t *testing.T) {
	t.Run("valid JSON output", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		var buf bytes.Buffer
		err = builder.AsJSON(t.Context(), &buf)

		require.NoError(t, err)
		require.NotEmpty(t, buf.String())

		// Verify it's valid JSON
		var bom cdx.BOM
		err = json.Unmarshal(buf.Bytes(), &bom)
		require.NoError(t, err)
	})
}

func TestAddEvidenceLocation(t *testing.T) {
	t.Run("add location to empty component", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1")

		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 1)
		require.Equal(t, "/path1", (*comp.Evidence.Occurrences)[0].Location)
	})

	t.Run("add multiple locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1", "/path2")

		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 2)
	})

	t.Run("avoid duplicate locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1")
		addEvidenceLocation(comp, "/path1")

		require.Len(t, *comp.Evidence.Occurrences, 1)
	})

	t.Run("locations are sorted", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path3", "/path1", "/path2")

		occurrences := *comp.Evidence.Occurrences
		require.Equal(t, "/path1", occurrences[0].Location)
		require.Equal(t, "/path2", occurrences[1].Location)
		require.Equal(t, "/path3", occurrences[2].Location)
	})

	t.Run("nil component", func(t *testing.T) {
		require.NotPanics(t, func() {
			addEvidenceLocation(nil, "/path1")
		})
	})

	t.Run("nil locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		require.NotPanics(t, func() {
			addEvidenceLocation(comp)
		})
	})
}

func TestSafeRef(t *testing.T) {
	tests := []struct {
		name     string
		bomRef   string
		wantLen  int
		contains string
	}{
		{
			name:     "ref with @ separator",
			bomRef:   "component@version",
			wantLen:  46, // "component@" + 36-char UUID
			contains: "component@",
		},
		{
			name:    "ref without @ separator",
			bomRef:  "component-ref",
			wantLen: 36, // Just UUID
		},
		{
			name:    "empty ref",
			bomRef:  "",
			wantLen: 36, // Just UUID
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeRef(tt.bomRef)

			require.Len(t, result, tt.wantLen)
			if tt.contains != "" {
				require.Contains(t, result, tt.contains)
			}
		})
	}
}

func TestSafeRefs_Component(t *testing.T) {
	t.Run("replace BOMRef in component", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref": "new-ref",
			},
		}

		comp := cdx.Component{
			BOMRef: "old-ref",
			Name:   "test",
		}

		result := refs.component(t.Context(), comp)

		require.Equal(t, "new-ref", result.BOMRef)
		require.Equal(t, "test", result.Name)
	})
}

func TestSafeRefs_Dependency(t *testing.T) {
	t.Run("dependency with no deps", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"comp-1": "safe-comp-1",
			},
		}

		dep := refs.dependency(t.Context(), "comp-1", nil)

		require.Equal(t, "safe-comp-1", dep.Ref)
		require.Nil(t, dep.Dependencies)
	})

	t.Run("dependency with deps", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"comp-1": "safe-comp-1",
				"dep-1":  "safe-dep-1",
				"dep-2":  "safe-dep-2",
			},
		}

		deps := []string{"dep-1", "dep-2"}
		dep := refs.dependency(t.Context(), "comp-1", &deps)

		require.Equal(t, "safe-comp-1", dep.Ref)
		require.NotNil(t, dep.Dependencies)
		require.Len(t, *dep.Dependencies, 2)
		require.Contains(t, *dep.Dependencies, "safe-dep-1")
		require.Contains(t, *dep.Dependencies, "safe-dep-2")
	})
}

func TestReplaceBOMReferences(t *testing.T) {
	t.Run("replace BOMReference in struct", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref": "new-ref",
			},
		}

		compo := cdx.Component{
			BOMRef: "old-ref",
		}

		compo = refs.component(t.Context(), compo)

		require.EqualValues(t, cdx.BOMReference("new-ref"), compo.BOMRef)
	})

	t.Run("replace nested BOMReference", func(t *testing.T) {
		refs := map[string]string{
			"crypto-ref": "safe-crypto-ref",
		}

		certProps := &cdx.CertificateProperties{
			SignatureAlgorithmRef: "crypto-ref",
		}
		cryptoProps := &cdx.CryptoProperties{
			CertificateProperties: certProps,
		}
		comp := cdx.Component{
			CryptoProperties: cryptoProps,
		}

		replaceBOMReferences(refs, reflect.ValueOf(&comp))

		require.Equal(t, cdx.BOMReference("safe-crypto-ref"), comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
	})

	t.Run("handle nil pointer", func(t *testing.T) {
		refs := map[string]string{
			"ref": "safe-ref",
		}

		var comp *cdx.Component

		require.NotPanics(t, func() {
			replaceBOMReferences(refs, reflect.ValueOf(comp))
		})
	})

	t.Run("handle slice of components", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref-1": "new-ref-1",
				"old-ref-2": "new-ref-2",
			},
		}

		compos := []cdx.Component{
			{BOMRef: "old-ref-1"},
			{BOMRef: "old-ref-2"},
		}

		for idx, compo := range compos {
			compos[idx] = refs.component(t.Context(), compo)
		}

		require.EqualValues(t, cdx.BOMReference("new-ref-1"), compos[0].BOMRef)
		require.EqualValues(t, cdx.BOMReference("new-ref-2"), compos[1].BOMRef)
	})

	t.Run("handle invalid value", func(t *testing.T) {
		refs := map[string]string{}

		require.NotPanics(t, func() {
			replaceBOMReferences(refs, reflect.Value{})
		})
	})
}

func TestBuilder_SafeRefs(t *testing.T) {
	t.Run("generate safe refs for all components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1"}
		builder.components["comp-2"] = &cdx.Component{BOMRef: "comp-2", Name: "test2"}

		safeRefs := builder.safeRefs()

		require.Len(t, safeRefs.refs, 2)
		require.Contains(t, safeRefs.refs, "comp-1")
		require.Contains(t, safeRefs.refs, "comp-2")
		require.NotEqual(t, "comp-1", safeRefs.refs["comp-1"])
		require.NotEqual(t, "comp-2", safeRefs.refs["comp-2"])
	})

	t.Run("skip nil components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1"}
		builder.components["comp-2"] = nil

		safeRefs := builder.safeRefs()

		require.Len(t, safeRefs.refs, 1)
		require.Contains(t, safeRefs.refs, "comp-1")
		require.NotContains(t, safeRefs.refs, "comp-2")
	})
}
