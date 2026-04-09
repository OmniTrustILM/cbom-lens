package registry_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	registry "github.com/CZERTAINLY/CBOM-lens/internal/walk/registry"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk/registry/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// helper: collect all entries yielded by WalkKey into a slice
func collectWalk(ctx context.Context, key registry.RegistryKey, keyPath, hive, view string, depth int, cfg model.Registry, c registry.Compiled) ([]model.Entry, []error) {
	var entries []model.Entry
	var errs []error
	registry.WalkKey(ctx, key, keyPath, hive, view, depth, cfg, c, func(e model.Entry, err error) bool {
		if err != nil {
			errs = append(errs, err)
		} else {
			entries = append(entries, e)
		}
		return true
	})
	return entries, errs
}

func TestWalkKey_REG_BINARY_yieldsEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"cert"}, nil)
	key.EXPECT().ReadValueType("cert").Return(uint32(3), nil) // REG_BINARY = 3
	key.EXPECT().ReadBinaryValue("cert").Return([]byte{0x01, 0x02, 0x03}, nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, err := registry.Compile(cfg)
	require.NoError(t, err)
	entries, errs := collectWalk(context.Background(), key, `SOFTWARE\App`, "HKLM", "64", 0, cfg, c)
	require.Empty(t, errs)
	require.Len(t, entries, 1)
	assert.Equal(t, "registry://HKLM:64/SOFTWARE/App/cert", entries[0].Location())

	info, err := entries[0].Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(3), info.Size())

	rc, err := entries[0].Open()
	require.NoError(t, err)
	b, _ := io.ReadAll(rc)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, b)
}

func TestWalkKey_REG_SZ_yieldsEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"pemcert"}, nil)
	key.EXPECT().ReadValueType("pemcert").Return(uint32(1), nil) // REG_SZ = 1
	key.EXPECT().ReadStringValue("pemcert").Return("-----BEGIN CERTIFICATE-----", nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, errs := collectWalk(context.Background(), key, `SOFTWARE`, "HKCU", "64", 0, cfg, c)
	require.Empty(t, errs)
	require.Len(t, entries, 1)
	assert.Equal(t, "registry://HKCU:64/SOFTWARE/pemcert", entries[0].Location())
	rc, _ := entries[0].Open()
	b, _ := io.ReadAll(rc)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----", string(b))
}

func TestWalkKey_REG_MULTI_SZ_joined(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"lines"}, nil)
	key.EXPECT().ReadValueType("lines").Return(uint32(7), nil) // REG_MULTI_SZ = 7
	key.EXPECT().ReadStringsValue("lines").Return([]string{"line1", "line2"}, nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
	rc, _ := entries[0].Open()
	b, _ := io.ReadAll(rc)
	assert.Equal(t, "line1\nline2", string(b))
}

func TestWalkKey_UnsupportedType_skipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"dword"}, nil)
	key.EXPECT().ReadValueType("dword").Return(uint32(4), nil) // REG_DWORD = 4 — skipped
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, errs := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	assert.Empty(t, entries)
	assert.Empty(t, errs)
}

func TestWalkKey_MaxValueSize_skips(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"big"}, nil)
	key.EXPECT().ReadValueType("big").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("big").Return(make([]byte, 10), nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 5} // 5 bytes max; value is 10
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	assert.Empty(t, entries)
}

func TestWalkKey_RecursesIntoSubkeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	root := mock.NewMockRegistryKey(ctrl)
	child := mock.NewMockRegistryKey(ctrl)

	root.EXPECT().ReadValueNames().Return([]string{}, nil)
	root.EXPECT().ReadSubKeyNames().Return([]string{"Child"}, nil)
	root.EXPECT().OpenSubKey("Child").Return(child, nil)

	child.EXPECT().ReadValueNames().Return([]string{"val"}, nil)
	child.EXPECT().ReadValueType("val").Return(uint32(3), nil)
	child.EXPECT().ReadBinaryValue("val").Return([]byte{0xFF}, nil)
	child.EXPECT().ReadSubKeyNames().Return([]string{}, nil)
	child.EXPECT().Close().Return(nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), root, `ROOT`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
	assert.Equal(t, "registry://HKLM:64/ROOT/Child/val", entries[0].Location())
}

func TestWalkKey_MaxDepth_stopsRecursion(t *testing.T) {
	ctrl := gomock.NewController(t)
	root := mock.NewMockRegistryKey(ctrl)
	// walkKey is called at depth=1 with MaxDepth=1.
	// ReadValueNames is called first (values at the limit depth are still processed).
	// The depth check fires before ReadSubKeyNames, so ReadSubKeyNames is never called.
	root.EXPECT().ReadValueNames().Return([]string{}, nil)
	// ReadSubKeyNames is NOT expected — the depth check prevents it.

	cfg := model.Registry{MaxDepth: 1}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), root, `ROOT`, "HKLM", "64", 1, cfg, c)
	assert.Empty(t, entries)
}

func TestWalkKey_IncludeKeyPattern_filters(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	// No mock expectations at all — key path "SOFTWARE" does not match the include pattern
	// "CryptoStore", so walkKey returns before calling ReadValueNames or ReadSubKeyNames.

	cfg := model.Registry{Include: model.RegistryFilter{Keys: []string{"CryptoStore"}}}
	c, err := registry.Compile(cfg)
	require.NoError(t, err)
	entries, _ := collectWalk(context.Background(), key, `SOFTWARE`, "HKLM", "64", 0, cfg, c)
	assert.Empty(t, entries)
}

func TestWalkKey_ExcludeKeyPattern_skipsSubtree(t *testing.T) {
	ctrl := gomock.NewController(t)
	root := mock.NewMockRegistryKey(ctrl)
	// Subkey "Telemetry" matches exclude pattern — OpenSubKey must NOT be called
	root.EXPECT().ReadValueNames().Return([]string{}, nil)
	root.EXPECT().ReadSubKeyNames().Return([]string{"Telemetry", "CryptoStore"}, nil)

	child := mock.NewMockRegistryKey(ctrl)
	root.EXPECT().OpenSubKey("CryptoStore").Return(child, nil)
	child.EXPECT().ReadValueNames().Return([]string{"cert"}, nil)
	child.EXPECT().ReadValueType("cert").Return(uint32(3), nil)
	child.EXPECT().ReadBinaryValue("cert").Return([]byte{0x01}, nil)
	child.EXPECT().ReadSubKeyNames().Return([]string{}, nil)
	child.EXPECT().Close().Return(nil)

	cfg := model.Registry{Exclude: model.RegistryFilter{Keys: []string{"Telemetry"}}}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), root, `SOFTWARE`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Location(), "CryptoStore")
}

func TestWalkKey_ExcludeValuePattern_skipsValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"cert", "junk"}, nil)
	key.EXPECT().ReadValueType("cert").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("cert").Return([]byte{0x01}, nil)
	// "junk" matches exclude pattern — ReadValueType not called for it
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{Exclude: model.RegistryFilter{Values: []string{"junk"}}}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Location(), "cert")
}

func TestWalkKey_EmptyInclude_passesAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"val"}, nil)
	key.EXPECT().ReadValueType("val").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("val").Return([]byte{0x01}, nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	// Empty include slice = no restriction
	cfg := model.Registry{Include: model.RegistryFilter{Keys: []string{}, Values: []string{}}}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
}

func TestWalkKey_ErrorOnOneValue_continues(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"bad", "good"}, nil)
	key.EXPECT().ReadValueType("bad").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("bad").Return(nil, errors.New("access denied"))
	key.EXPECT().ReadValueType("good").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("good").Return([]byte{0x02}, nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, errs := collectWalk(context.Background(), key, `KEY`, "HKLM", "64", 0, cfg, c)
	assert.Len(t, entries, 1) // "good" still yielded despite "bad" failing
	assert.Len(t, errs, 1)    // read error from "bad" propagated via yield
}

func TestWalkKey_ContextCancelled_stops(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	// No expectations — any call to the mock would panic, proving early-exit is exercised.

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before walk starts

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(ctx, key, `KEY`, "HKLM", "64", 0, cfg, c)
	assert.Empty(t, entries)
}

func TestCompile_InvalidPattern_returnsError(t *testing.T) {
	cfg := model.Registry{Include: model.RegistryFilter{Keys: []string{"[invalid"}}}
	_, err := registry.Compile(cfg)
	require.Error(t, err)
}

func TestLocationFormat_backslashNormalised(t *testing.T) {
	ctrl := gomock.NewController(t)
	key := mock.NewMockRegistryKey(ctrl)
	key.EXPECT().ReadValueNames().Return([]string{"cert"}, nil)
	key.EXPECT().ReadValueType("cert").Return(uint32(3), nil)
	key.EXPECT().ReadBinaryValue("cert").Return([]byte{0x01}, nil)
	key.EXPECT().ReadSubKeyNames().Return([]string{}, nil)

	cfg := model.Registry{MaxValueSize: 0}
	c, _ := registry.Compile(cfg)
	entries, _ := collectWalk(context.Background(), key, `SOFTWARE\Vendor\App`, "HKLM", "64", 0, cfg, c)
	require.Len(t, entries, 1)
	assert.Equal(t, "registry://HKLM:64/SOFTWARE/Vendor/App/cert", entries[0].Location())
}
