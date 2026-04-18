package registry

// Export unexported symbols for white-box testing in package registry_test.
// This file is only compiled during tests.

var Compile = compile
var WalkKey = walkKey

type Compiled = compiled
