package agent

import (
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

const (
	// defaultWaitMS is how long a poll holds until the hello reply sets another
	// value.
	defaultWaitMS = 25_000
	// halfWaitMS is the wait of the second step, or the base wait if that is shorter.
	halfWaitMS = 10_000
	// shortGap is the pause between two short polls.
	shortGap = 2 * time.Second
	// cutsPerStep is how many held polls in a row must be cut before the plan
	// takes the next step.
	cutsPerStep = 2
	// recoverAfter is how long the plan stays degraded before it tries the full
	// wait once, so a short outage cannot leave it degraded for good.
	recoverAfter = 10 * time.Minute
)

// pollStep is one rung of the fallback.
type pollStep int

const (
	stepLong  pollStep = iota // wait_ms as the server says, normally 25 s
	stepHalf                  // wait_ms 10 s
	stepShort                 // wait_ms 0, a poll every 2 s
)

// pollPlan decides how long the next poll holds: two cuts in a row shorten the
// wait to 10 s, two more switch to short polls, and after ten minutes it tries the
// full wait once. The poll loop owns it, so it needs no lock.
type pollPlan struct {
	baseWaitMS int
	step       pollStep
	cuts       int
	since      time.Time
	probing    bool
}

func newPollPlan() *pollPlan {
	return &pollPlan{baseWaitMS: defaultWaitMS}
}

// setBase adopts the wait that Tellagen asked for. A value of zero or less keeps
// the default.
func (p *pollPlan) setBase(waitMS int) {
	if waitMS > 0 {
		p.baseWaitMS = waitMS
	}
}

// next returns the wait and mode of the next poll, and the pause that follows it.
func (p *pollPlan) next(now time.Time) (waitMS int, mode string, gap time.Duration) {
	if p.step != stepLong && !p.probing && now.Sub(p.since) >= recoverAfter {
		p.probing = true
	}
	step := p.step
	if p.probing {
		step = stepLong
	}
	switch step {
	case stepShort:
		return 0, protocol.PollModeShort, shortGap
	case stepHalf:
		return min(p.baseWaitMS, halfWaitMS), protocol.PollModeLong, 0
	}
	return p.baseWaitMS, protocol.PollModeLong, 0
}

// success records a poll that came back whole.
func (p *pollPlan) success() {
	p.cuts = 0
	if p.probing {
		p.probing, p.step = false, stepLong
	}
}

// cut records a poll that did not come back whole.
func (p *pollPlan) cut(now time.Time) {
	if p.probing {
		p.probing, p.since, p.cuts = false, now, 0
		return
	}
	p.cuts++
	if p.cuts >= cutsPerStep && p.step < stepShort {
		p.step++
		p.cuts, p.since = 0, now
	}
}
