package settings

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// RefreshInterval is how long a secret read from a file is trusted, so a
	// rotated secret takes effect within this time.
	RefreshInterval = 60 * time.Second
	// FileWait is how long the proxy waits at start for a secret file that a
	// sidecar has not written yet.
	FileWait = 2 * time.Minute
	// fileWaitPoll is the pause between two reads while waiting for a file.
	fileWaitPoll = time.Second
)

// ErrSecretMissing means a secret file does not exist yet or holds only white
// space. A Vault sidecar may still be writing it, so start waits for it.
var ErrSecretMissing = errors.New("the secret file is missing or empty")

// Secret is one setting that can come from an environment variable or from a file.
// A file is read again after RefreshInterval, so rotation needs no restart.
type Secret struct {
	name   string
	inline string
	path   string
	now    func() time.Time
	read   func(string) ([]byte, error)

	mu      sync.Mutex
	value   string
	loaded  bool
	readAt  time.Time
	lastErr error
}

// Name is the setting without the _FILE suffix, such as TELLAGEN_PROXY_TOKEN.
func (s *Secret) Name() string { return s.name }

// FromFile reports whether the value comes from a file.
func (s *Secret) FromFile() bool { return s.path != "" }

// Path is the file the value comes from, or "".
func (s *Secret) Path() string { return s.path }

// Source names the variable that holds the secret, such as
// TELLAGEN_PROXY_TOKEN_FILE. It never contains the secret.
func (s *Secret) Source() string {
	if s.path != "" {
		return s.name + "_FILE"
	}
	return s.name
}

// Value returns the secret, reading the file again when the last read is older
// than RefreshInterval. If that read fails and an earlier one worked, the earlier
// value stays in use, so a sidecar that is rewriting the file does not stop the
// proxy. Err shows the failed read.
func (s *Secret) Value() (string, error) {
	if s.path == "" {
		return s.inline, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded && s.now().Sub(s.readAt) < RefreshInterval {
		return s.value, nil
	}
	err := s.reloadLocked()
	if err != nil && s.loaded {
		return s.value, nil
	}
	return s.value, err
}

// Reload reads the file again now. The proxy calls it for the proxy token after a
// 401 from Tellagen. The returned error is the read error, even when an earlier
// value is still in use.
func (s *Secret) Reload() (string, error) {
	if s.path == "" {
		return s.inline, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.reloadLocked()
	return s.value, err
}

// Err returns the error of the latest read, or nil.
func (s *Secret) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func (s *Secret) reloadLocked() error {
	s.readAt = s.now()
	data, err := s.read(s.path)
	if err == nil {
		value := strings.TrimSpace(string(data))
		if value == "" {
			err = ErrSecretMissing
		} else {
			s.value, s.loaded, s.lastErr = value, true, nil
			return nil
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		err = ErrSecretMissing
	}
	s.lastErr = fmt.Errorf("%s %s: %w", s.Source(), s.path, err)
	return s.lastErr
}

// WaitForFiles blocks until every secret file can be read. It waits only for
// files that are missing or empty, and gives up after wait. Any other failure,
// such as a permission error, is final at once, because waiting does not fix it.
// onWaiting is called with the files still missing, before each pause.
func WaitForFiles(ctx context.Context, wait time.Duration, secrets []*Secret, onWaiting func(missing []string)) error {
	return waitForFiles(ctx, wait, fileWaitPoll, secrets, onWaiting)
}

func waitForFiles(ctx context.Context, wait, poll time.Duration, secrets []*Secret, onWaiting func(missing []string)) error {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		var missing []string
		for _, secret := range secrets {
			if !secret.FromFile() {
				continue
			}
			if _, err := secret.Reload(); err != nil {
				if !errors.Is(err, ErrSecretMissing) {
					return err
				}
				missing = append(missing, secret.Path())
			}
		}
		if len(missing) == 0 {
			return nil
		}
		if onWaiting != nil {
			onWaiting(missing)
		}
		pause := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			pause.Stop()
			return ctx.Err()
		case <-deadline.C:
			pause.Stop()
			return fmt.Errorf("waited %s for %s, which is still missing or empty. Check that the sidecar or mount that writes it is running", wait, strings.Join(missing, ", "))
		case <-pause.C:
		}
	}
}

// FileState describes a file for the doctor: who owns it, which mode it has and
// which user the proxy runs as.
type FileState struct {
	Exists     bool
	Mode       fs.FileMode
	OwnerUID   int
	ProcessUID int
	Err        error
}

// Inspect reads the state of path. It does not read the file.
func Inspect(path string) FileState {
	state := FileState{OwnerUID: -1, ProcessUID: os.Getuid()}
	info, err := os.Stat(path)
	if err != nil {
		state.Err = err
		return state
	}
	state.Exists = true
	state.Mode = info.Mode().Perm()
	state.OwnerUID = ownerUID(info)
	return state
}
