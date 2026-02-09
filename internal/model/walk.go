package model

import (
	"io"
	"io/fs"
)

// Entry abstracts the filesystem entry - it does not matter if a file is from
// filesystem or OCI image. It allows to get the location, Open the file and perform a stat
type Entry interface {
	Location() string
	Open() (io.ReadCloser, error)
	Stat() (fs.FileInfo, error)
}
