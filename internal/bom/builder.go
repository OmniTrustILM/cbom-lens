package bom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

var programVersion string

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		programVersion = "unknown"
	} else {
		programVersion = info.Main.Version
	}
}

// Builder is a builder pattern for a CycloneDX BOM structure
type Builder struct {
	version      cdx.SpecVersion
	schema       string
	components   map[string]*cdx.Component
	dependencies map[string]*[]string
	properties   []cdx.Property
	counter      *stats.Stats
}

func NewBuilder(config model.CBOM) (*Builder, error) {
	var versions = map[string]cdx.SpecVersion{
		"1.6": cdx.SpecVersion1_6,
	}
	var schemas = map[cdx.SpecVersion]string{
		cdx.SpecVersion1_6: "https://cyclonedx.org/schema/bom-1.6.schema.json",
	}

	version, ok := versions[config.Version]
	if !ok {
		return nil, fmt.Errorf("unsupported cbom spec version %s", config.Version)
	}
	schema, ok := schemas[version]
	if !ok {
		return nil, fmt.Errorf("unknown json schema for version %s", version)
	}

	return &Builder{
		version:      version,
		schema:       schema,
		components:   make(map[string]*cdx.Component),
		dependencies: make(map[string]*[]string),
		properties:   []cdx.Property{},
	}, nil
}

func (b *Builder) WithCounter(counter *stats.Stats) *Builder {
	b.counter = counter
	return b
}

func (b *Builder) AppendDetections(ctx context.Context, detections ...model.Detection) *Builder {
	for _, d := range detections {
		b.appendDetection(ctx, d)
	}
	return b
}

func (b *Builder) appendDetection(ctx context.Context, detection model.Detection) {
	for _, dep := range detection.Dependencies {
		if dep.Ref == "" {
			continue
		}
		_, ok := b.dependencies[dep.Ref]
		if ok {
			slog.DebugContext(ctx, "ignoring dependency: already stored", "ref", dep.Ref)
			continue
		}
		b.dependencies[dep.Ref] = dep.Dependencies
	}

	for _, compo := range detection.Components {
		if compo.BOMRef == "" || compo.Name == "" {
			continue
		}
		stored, ok := b.components[compo.BOMRef]
		if ok {
			addEvidenceLocation(stored, detection.Location)
			continue
		}
		addEvidenceLocation(&compo, detection.Location)
		b.components[compo.BOMRef] = &compo
	}
}

// BOM returns a cdx.BOM based on a data inside the Builder
func (b *Builder) BOM(ctx context.Context) cdx.BOM {
	safeRefs := b.safeRefs()

	components := make([]cdx.Component, 0, len(b.components))
	for _, compop := range b.components {
		if compop == nil {
			continue
		}
		components = append(components, safeRefs.component(ctx, *compop))
	}

	dependencies := make([]cdx.Dependency, 0, len(b.dependencies))
	for bomRef, depsp := range b.dependencies {
		dependencies = append(dependencies, safeRefs.dependency(ctx, bomRef, depsp))
	}

	var metadataProperties *[]cdx.Property
	if b.counter != nil {
		p := bomStatistics(b.counter)
		metadataProperties = &p
	}

	bom := cdx.BOM{
		JSONSchema:   "https://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Lifecycles: &[]cdx.Lifecycle{
				{
					Name:        "",
					Phase:       "operations",
					Description: "",
				},
			},
			// This can't be not nil otherwise this error will happen
			// json: error calling MarshalJSON for type *cyclonedx.ToolsChoice: unexpected end of JSON input
			Component: &cdx.Component{
				Type:    "application",
				Name:    "CBOM-Lens",
				Version: programVersion,
				Manufacturer: &cdx.OrganizationalEntity{
					Name:    "CZERTAINLY",
					Address: &cdx.PostalAddress{},
					URL: &[]string{
						"https://www.czertainly.com",
					},
				},
			},
			Properties: metadataProperties,
		},
		Components:   &components,
		Dependencies: &dependencies,
		Properties:   &b.properties,
	}
	return bom
}

// AsJSON encode the BOM into JSON format
func (b *Builder) AsJSON(ctx context.Context, w io.Writer) error {
	bom := b.BOM(ctx)
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom)
}

// Add (append) an evidence.occurrence location if non-empty.
// ensures location is present only once
func addEvidenceLocation(c *cdx.Component, locations ...string) {
	if c == nil || locations == nil {
		return
	}
	if c.Evidence == nil {
		c.Evidence = &cdx.Evidence{}
	}
	if c.Evidence.Occurrences == nil {
		c.Evidence.Occurrences = &[]cdx.EvidenceOccurrence{}
	}

	stored := make(map[string]struct{})
	for _, occ := range *c.Evidence.Occurrences {
		stored[occ.Location] = struct{}{}
	}
	for _, loc := range locations {
		stored[loc] = struct{}{}
	}

	if len(stored) == 0 {
		return
	}

	occurences := make([]cdx.EvidenceOccurrence, 0, len(stored))
	for _, loc := range slices.Sorted(maps.Keys(stored)) {
		occurences = append(occurences, cdx.EvidenceOccurrence{
			Location: loc,
		})
	}

	c.Evidence.Occurrences = &occurences
}

func bomStatistics(counter *stats.Stats) []cdx.Property {
	stats := maps.Collect(counter.Stats())
	var props = make([]cdx.Property, 0, len(stats))
	for _, name := range slices.Sorted(maps.Keys(stats)) {
		props = append(props, cdx.Property{
			Name:  name,
			Value: stats[name],
		})
	}
	return props
}

type refs map[string]string

func (r refs) get(ctx context.Context, key string) string {
	safe, ok := r[key]
	if !ok {
		slog.WarnContext(ctx, "unknown bom-ref to replace, generating a new one", "original", key, "new", safe)
		safe = uuid.New().String()
		r[key] = safe
	}
	return safe
}

type safeRefs struct {
	refs refs
}

func (b Builder) safeRefs() safeRefs {
	var refs = make(map[string]string, len(b.components))
	for _, compop := range b.components {
		if compop == nil {
			continue
		}
		if _, ok := refs[compop.BOMRef]; !ok {
			refs[compop.BOMRef] = safeRef(compop.BOMRef)
		}
	}
	return safeRefs{refs: refs}
}

func (s safeRefs) component(ctx context.Context, compo cdx.Component) cdx.Component {
	safe := s.refs.get(ctx, compo.BOMRef)
	compo.BOMRef = safe

	replaceBOMReferences(s.refs, reflect.ValueOf(&compo))

	return compo
}

func (s safeRefs) dependency(ctx context.Context, bomRef string, depsp *[]string) cdx.Dependency {
	safe := s.refs.get(ctx, bomRef)
	if depsp != nil {
		deps := make([]string, len(*depsp))
		for idx, dep := range *depsp {
			deps[idx] = s.refs[dep]
		}
		depsp = &deps
	}

	return cdx.Dependency{
		Ref:          safe,
		Dependencies: depsp,
	}
}

func safeRef(bomRef string) string {
	uid := uuid.New()
	before, _, ok := strings.Cut(bomRef, "@")
	if !ok {
		return uid.String()
	}
	return before + "@" + uid.String()
}

func replaceBOMReferences(refs map[string]string, v reflect.Value) {
	if !v.IsValid() {
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		replaceBOMReferences(refs, v.Elem())

	case reflect.Interface:
		if v.IsNil() {
			return
		}
		replaceBOMReferences(refs, v.Elem())

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if !field.CanSet() {
				continue
			}

			// Check if this field is a BOMReference
			if field.Type() == reflect.TypeFor[cdx.BOMReference]() {
				oldRef := field.Interface().(cdx.BOMReference)
				if oldRef != "" {
					if safeRef, ok := refs[string(oldRef)]; ok {
						field.SetString(safeRef)
					}
				}
			} else {
				replaceBOMReferences(refs, field)
			}
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			replaceBOMReferences(refs, v.Index(i))
		}

	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			replaceBOMReferences(refs, iter.Value())
		}
	}
}
