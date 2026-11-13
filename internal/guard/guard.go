// Package guard checks a query before the proxy sends it to Grafana. A query it
// cannot read is refused.
package guard

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// MaxQueryBytes is the longest query the proxy accepts.
const MaxQueryBytes = 8 << 10

// Rejection says why a query was refused. Message and Hint tell the AI what would
// pass.
type Rejection struct {
	Code    string
	Message string
	Hint    *protocol.Limits
}

// Error implements error.
func (r *Rejection) Error() string {
	return r.Code + ": " + r.Message
}

func refused(format string, args ...any) *Rejection {
	return &Rejection{Code: protocol.CodeQueryGuardFailed, Message: fmt.Sprintf(format, args...)}
}

func checkLength(language, expr string) *Rejection {
	switch {
	case strings.TrimSpace(expr) == "":
		return refused("the %s query is empty", language)
	case len(expr) > MaxQueryBytes:
		return refused("the %s query has %d bytes, more than the %d allowed", language, len(expr), MaxQueryBytes)
	}
	return nil
}

// Range holds the time window of a query and how far back its expression reads
// beyond that window.
type Range struct {
	Start    time.Time
	End      time.Time
	StepS    int
	Lookback time.Duration
}

// CheckRange applies the range and points limits to a range query. A limit of zero
// is not set. The range includes the expression's own range vectors.
func CheckRange(r Range, limits protocol.Limits) *Rejection {
	if r.Start.IsZero() || r.End.IsZero() {
		return refused("the query needs a start and an end time")
	}
	if !r.End.After(r.Start) {
		return refused("the end time must be after the start time")
	}
	if rejection := checkWindow(r.End.Sub(r.Start)+r.Lookback, limits); rejection != nil {
		return rejection
	}
	if r.StepS < 0 {
		return refused("step_s must not be negative")
	}
	if r.StepS == 0 || limits.MaxPoints <= 0 {
		return nil
	}
	window := int64(r.End.Sub(r.Start) / time.Second)
	points := window/int64(r.StepS) + 1
	if points <= int64(limits.MaxPoints) {
		return nil
	}
	return &Rejection{
		Code:    protocol.CodeQueryGuardFailed,
		Message: fmt.Sprintf("the query asks for %d points per series, more than the %d allowed. Raise step_s to at least %d", points, limits.MaxPoints, window/int64(limits.MaxPoints)+1),
		Hint:    &protocol.Limits{MaxPoints: limits.MaxPoints},
	}
}

// CheckLookback applies the range limit to an instant query, which reads only what
// its expression reaches back to.
func CheckLookback(lookback time.Duration, limits protocol.Limits) *Rejection {
	return checkWindow(lookback, limits)
}

func checkWindow(window time.Duration, limits protocol.Limits) *Rejection {
	if limits.MaxRangeS <= 0 || window <= time.Duration(limits.MaxRangeS)*time.Second {
		return nil
	}
	return &Rejection{
		Code:    protocol.CodePolicyRangeExceeded,
		Message: fmt.Sprintf("range %s exceeds %s, counting range vectors and offsets", formatDuration(window), formatDuration(time.Duration(limits.MaxRangeS)*time.Second)),
		Hint:    &protocol.Limits{MaxRangeS: limits.MaxRangeS},
	}
}

func formatDuration(d time.Duration) string {
	hours := d.Hours()
	if hours >= 1 && hours == float64(int64(hours)) {
		return strconv.FormatInt(int64(hours), 10) + "h"
	}
	return d.Round(time.Second).String()
}

// saturatingAdd adds two non-negative durations and stops at the maximum instead
// of wrapping round to a value under a limit.
func saturatingAdd(a, b time.Duration) time.Duration {
	if a > maxDuration-b {
		return maxDuration
	}
	return a + b
}

const maxDuration = time.Duration(1<<63 - 1)

func absDuration(d time.Duration) time.Duration {
	if d == -d && d != 0 {
		return maxDuration
	}
	if d < 0 {
		return -d
	}
	return d
}
