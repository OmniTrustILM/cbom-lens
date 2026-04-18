package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

// Windows REG_* type constants. These are fixed Windows API values.
const (
	regSZ       uint32 = 1
	regExpandSZ uint32 = 2
	regBinary   uint32 = 3
	regMultiSZ  uint32 = 7
)

// compiled holds pre-compiled regex filters.
type compiled struct {
	includeKeys   []*regexp.Regexp
	excludeKeys   []*regexp.Regexp
	includeValues []*regexp.Regexp
	excludeValues []*regexp.Regexp
}

// compile pre-compiles all regex patterns in the Registry config.
// Returns an error immediately if any pattern is invalid.
func compile(cfg model.Registry) (compiled, error) {
	var c compiled
	var err error
	if c.includeKeys, err = compileAll(cfg.Include.Keys); err != nil {
		return c, fmt.Errorf("registry include.keys: %w", err)
	}
	if c.excludeKeys, err = compileAll(cfg.Exclude.Keys); err != nil {
		return c, fmt.Errorf("registry exclude.keys: %w", err)
	}
	if c.includeValues, err = compileAll(cfg.Include.Values); err != nil {
		return c, fmt.Errorf("registry include.values: %w", err)
	}
	if c.excludeValues, err = compileAll(cfg.Exclude.Values); err != nil {
		return c, fmt.Errorf("registry exclude.values: %w", err)
	}
	return c, nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// matchesAny reports whether s matches any of the compiled patterns.
func matchesAny(s string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// valueAllowed reports whether a value name passes the include/exclude value filters.
func valueAllowed(name string, c compiled) bool {
	if len(c.includeValues) > 0 && !matchesAny(name, c.includeValues) {
		return false
	}
	if len(c.excludeValues) > 0 && matchesAny(name, c.excludeValues) {
		return false
	}
	return true
}

// normaliseKey converts backslash separators to forward slashes for URI embedding.
func normaliseKey(keyPath string) string {
	return strings.ReplaceAll(keyPath, `\`, "/")
}

// walkKey recursively walks key and its subkeys, yielding a registryEntry per matching value.
// keyPath is the path relative to the hive root (backslash-separated, as from the Windows API).
// Returns false if the yield function signalled stop.
func walkKey(
	ctx context.Context,
	key RegistryKey,
	keyPath string,
	hive string,
	view string,
	depth int,
	cfg model.Registry,
	c compiled,
	yield func(model.Entry, error) bool,
) bool {
	if ctx.Err() != nil {
		return false
	}

	normPath := normaliseKey(keyPath)

	// Exclude filter prunes the entire subtree (values and all subkeys).
	if len(c.excludeKeys) > 0 && matchesAny(normPath, c.excludeKeys) {
		return true
	}

	// Include filter applies only to value emission.  Subkey traversal
	// continues regardless so that a pattern like "CryptoStore" can match
	// SOFTWARE/CryptoStore even when the scan root is SOFTWARE.
	if len(c.includeKeys) == 0 || matchesAny(normPath, c.includeKeys) {
		names, err := key.ReadValueNames()
		if err != nil {
			if !yield(nil, fmt.Errorf("registry: ReadValueNames %s: %w", normPath, err)) {
				return false
			}
		}
		for _, name := range names {
			if ctx.Err() != nil {
				return false
			}
			if !valueAllowed(name, c) {
				continue
			}
			data, ok, err := convertValue(key, name)
			if err != nil {
				if !yield(nil, fmt.Errorf("%s:%s/%s: %w", hive, view, normPath, err)) {
					return false
				}
				continue
			}
			if !ok {
				continue // unsupported type — silently skip
			}
			if cfg.MaxValueSize > 0 && len(data) > cfg.MaxValueSize {
				continue
			}
			locationName := name
			if locationName == "" {
				locationName = "(Default)"
			}
			location := fmt.Sprintf("registry://%s:%s/%s/%s", hive, view, normPath, locationName)
			if normPath == "" {
				location = fmt.Sprintf("registry://%s:%s/%s", hive, view, locationName)
			}
			entry := registryEntry{location: location, data: data}
			if !yield(entry, nil) {
				return false
			}
		}
	}

	// Recurse into subkeys unless at depth limit.
	// When MaxDepth == 0 (unlimited) the guard is skipped and the entire
	// subtree is walked.  This is safe because the Windows registry is a
	// strict tree — the hive format cannot contain cycles or symbolic links
	// between keys, so recursion always terminates.
	if cfg.MaxDepth > 0 && depth >= cfg.MaxDepth {
		return true
	}
	subNames, err := key.ReadSubKeyNames()
	if err != nil {
		return yield(nil, fmt.Errorf("registry: ReadSubKeyNames %s: %w", normPath, err))
	}
	for _, sub := range subNames {
		if ctx.Err() != nil {
			return false
		}
		subPath := sub
		if keyPath != "" {
			subPath = keyPath + `\` + sub
		}
		normSubPath := normaliseKey(subPath)
		// Pre-check exclude on the subkey path before opening it
		if len(c.excludeKeys) > 0 && matchesAny(normSubPath, c.excludeKeys) {
			continue
		}
		subKey, err := key.OpenSubKey(sub)
		if err != nil {
			if !yield(nil, fmt.Errorf("registry: OpenSubKey %s: %w", normSubPath, err)) {
				return false
			}
			continue
		}
		cont := walkKey(ctx, subKey, subPath, hive, view, depth+1, cfg, c, yield)
		_ = subKey.Close()
		if !cont {
			return false
		}
	}
	return true
}

// convertValue reads and converts a registry value to bytes.
// Returns (bytes, true, nil) for supported types on success.
// Returns (nil, false, nil) for unsupported types (silently skipped).
// Returns (nil, false, err) when a read error occurs — the caller should propagate the error.
func convertValue(key RegistryKey, name string) ([]byte, bool, error) {
	valType, err := key.ReadValueType(name)
	if err != nil {
		return nil, false, fmt.Errorf("registry: ReadValueType %s: %w", name, err)
	}
	switch valType {
	case regBinary:
		b, err := key.ReadBinaryValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadBinaryValue %s: %w", name, err)
		}
		return b, true, nil
	case regSZ, regExpandSZ:
		s, err := key.ReadStringValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadStringValue %s: %w", name, err)
		}
		return []byte(s), true, nil
	case regMultiSZ:
		ss, err := key.ReadStringsValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadStringsValue %s: %w", name, err)
		}
		return []byte(strings.Join(ss, "\n")), true, nil
	default:
		return nil, false, nil // unsupported type — silently skip
	}
}

// registryEntry implements model.Entry for a single registry value.
type registryEntry struct {
	location string
	data     []byte
}

func (e registryEntry) Location() string { return e.location }

func (e registryEntry) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(e.data)), nil
}

func (e registryEntry) Stat() (fs.FileInfo, error) {
	return registryStat{name: e.location[strings.LastIndex(e.location, "/")+1:], size: int64(len(e.data))}, nil
}

// registryStat is a minimal fs.FileInfo for a registry value.
type registryStat struct {
	name string
	size int64
}

func (s registryStat) Name() string       { return s.name }
func (s registryStat) Size() int64        { return s.size }
func (s registryStat) Mode() fs.FileMode  { return 0 }
func (s registryStat) ModTime() time.Time { return time.Time{} }
func (s registryStat) IsDir() bool        { return false }
func (s registryStat) Sys() any           { return nil }
