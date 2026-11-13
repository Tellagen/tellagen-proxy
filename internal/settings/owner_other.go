//go:build !unix

package settings

import "io/fs"

func ownerUID(fs.FileInfo) int { return -1 }
