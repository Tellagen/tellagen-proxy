package agent

import (
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

var planStart = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

type planStep struct {
	wait int
	mode string
	gap  time.Duration
}

func nextOf(p *pollPlan, now time.Time) planStep {
	wait, mode, gap := p.next(now)
	return planStep{wait, mode, gap}
}

var (
	longPoll  = planStep{25_000, protocol.PollModeLong, 0}
	halfPoll  = planStep{10_000, protocol.PollModeLong, 0}
	shortPoll = planStep{0, protocol.PollModeShort, 2 * time.Second}
)

func TestPlanStartsWithTheFullWait(t *testing.T) {
	if got := nextOf(newPollPlan(), planStart); got != longPoll {
		t.Errorf("first poll = %+v, want %+v", got, longPoll)
	}
}

func TestPlanHalvesTheWaitAfterTwoCutsInARow(t *testing.T) {
	p := newPollPlan()
	p.cut(planStart)
	if got := nextOf(p, planStart); got != longPoll {
		t.Errorf("after one cut = %+v, want the full wait", got)
	}
	p.cut(planStart)
	if got := nextOf(p, planStart); got != halfPoll {
		t.Errorf("after two cuts = %+v, want %+v", got, halfPoll)
	}
}

func TestPlanSwitchesToShortPollsAfterTwoMoreCuts(t *testing.T) {
	p := newPollPlan()
	for range 4 {
		p.cut(planStart)
	}
	if got := nextOf(p, planStart); got != shortPoll {
		t.Errorf("after four cuts = %+v, want %+v", got, shortPoll)
	}
	for range 10 {
		p.cut(planStart)
	}
	if got := nextOf(p, planStart); got != shortPoll {
		t.Errorf("more cuts must stay at short polls, got %+v", got)
	}
}

func TestPlanCutsMustBeInARow(t *testing.T) {
	p := newPollPlan()
	for range 5 {
		p.cut(planStart)
		p.success()
	}
	if got := nextOf(p, planStart); got != longPoll {
		t.Errorf("alternating cuts and successes = %+v, want the full wait", got)
	}
}

func TestPlanSuccessDoesNotLeaveADegradedStepByItself(t *testing.T) {
	p := newPollPlan()
	p.cut(planStart)
	p.cut(planStart)
	p.success()
	if got := nextOf(p, planStart.Add(time.Minute)); got != halfPoll {
		t.Errorf("after a success inside the recovery window = %+v, want to stay at %+v", got, halfPoll)
	}
}

func TestPlanTriesTheFullWaitOnceAfterTenMinutes(t *testing.T) {
	p := newPollPlan()
	for range 4 {
		p.cut(planStart)
	}
	if got := nextOf(p, planStart.Add(recoverAfter-time.Second)); got != shortPoll {
		t.Fatalf("before the recovery time = %+v", got)
	}
	probeAt := planStart.Add(recoverAfter)
	if got := nextOf(p, probeAt); got != longPoll {
		t.Fatalf("at the recovery time = %+v, want one full-wait poll", got)
	}

	// A probe that is cut puts the plan back where it was and waits another 10 minutes.
	p.cut(probeAt)
	if got := nextOf(p, probeAt.Add(time.Second)); got != shortPoll {
		t.Errorf("after a cut probe = %+v, want %+v", got, shortPoll)
	}
	if got := nextOf(p, probeAt.Add(recoverAfter)); got != longPoll {
		t.Errorf("a second probe must follow 10 minutes later, got %+v", got)
	}

	// A probe that works ends the fallback.
	p.success()
	if got := nextOf(p, probeAt.Add(recoverAfter+time.Second)); got != longPoll {
		t.Errorf("after a good probe = %+v, want the full wait for good", got)
	}
}

func TestPlanFollowsTheWaitTellagenAsks(t *testing.T) {
	p := newPollPlan()
	p.setBase(20_000)
	if got := nextOf(p, planStart); got.wait != 20_000 {
		t.Errorf("wait = %d, want 20000", got.wait)
	}
	p.cut(planStart)
	p.cut(planStart)
	if got := nextOf(p, planStart); got.wait != 10_000 {
		t.Errorf("halved wait = %d, want 10000", got.wait)
	}
	p.setBase(0)
	if p.baseWaitMS != 20_000 {
		t.Errorf("setBase(0) changed the base to %d", p.baseWaitMS)
	}
	p.setBase(4_000)
	if got := nextOf(p, planStart); got.wait != 4_000 {
		t.Errorf("a base below the halved wait must stay, got %d", got.wait)
	}
}
