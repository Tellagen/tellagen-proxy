package agent

import (
	"fmt"
	"strconv"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// startCommand runs a command in its own goroutine. A command that is already
// running is ignored, but a new attempt of it runs, because Tellagen would refuse
// the result of the first one.
func (a *Agent) startCommand(command protocol.Command) {
	key := command.CommandID + "/" + strconv.Itoa(command.Attempt)
	a.mu.Lock()
	if _, running := a.running[key]; running {
		a.mu.Unlock()
		return
	}
	a.running[key] = struct{}{}
	a.mu.Unlock()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			a.mu.Lock()
			delete(a.running, key)
			a.mu.Unlock()
		}()
		a.runCommand(command)
	}()
}

func (a *Agent) runCommand(command protocol.Command) {
	requestedAt := a.now()
	result := a.execute(command)
	finishedAt := a.now()
	if result.DurationMS == 0 {
		result.DurationMS = int(finishedAt.Sub(requestedAt) / time.Millisecond)
	}
	result.AttemptToken = command.AttemptToken

	a.metrics.commands.WithLabelValues(result.Status).Inc()
	a.metrics.duration.Observe(float64(result.DurationMS) / 1000)
	line := newAuditLine(command, result, requestedAt, finishedAt, a.cfg.Policy.Revision(), a.cfg.Policy.RedactionOff())
	if err := a.audit.write(line); err != nil {
		a.log.Error("cannot write the audit line", "command_id", command.CommandID, "error", err)
	}
	a.post(command, result)
}

// execute runs the command and turns a panic into an error result, so one bad
// command cannot take the proxy down.
func (a *Agent) execute(command protocol.Command) (result protocol.CommandResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			a.log.Error("a command panicked", "command_id", command.CommandID, "panic", fmt.Sprint(recovered))
			result = protocol.CommandResult{
				Status: protocol.StatusError,
				Error:  &protocol.ResultError{Code: protocol.CodeSourceUnavailable, Message: "the proxy failed while running this command", Retryable: true},
			}
		}
	}()
	return a.cfg.Executor.Execute(a.runCtx, command)
}

// post sends the result. It tries again after any error except a refusal, up to
// resultAttempts times. Tellagen sends the command again if it still wants it.
func (a *Agent) post(command protocol.Command, result protocol.CommandResult) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := a.cfg.Backend.PostResult(a.postCtx, command.CommandID, result)
		if err == nil {
			return
		}
		switch hub.Classify(a.postCtx, err) {
		case hub.KindStopped:
			a.log.Warn("shutdown ended before the result was sent", "command_id", command.CommandID)
			return
		case hub.KindRefused:
			a.log.Info("Tellagen no longer wants this result", "command_id", command.CommandID, "error", err)
			return
		}
		if attempt >= resultAttempts {
			a.log.Error("giving up on sending a result. Tellagen will send the command again when its lease ends", "command_id", command.CommandID, "error", err)
			return
		}
		a.log.Warn("sending a result failed. Trying again", "command_id", command.CommandID, "attempt", attempt, "error", err)
		if a.sleep(a.postCtx, a.jitter(delay)) != nil {
			return
		}
		delay *= 2
	}
}

// drain waits for running commands at shutdown. Commands that outlast the grace
// are cancelled, and their cancelled results are sent.
func (a *Agent) drain() {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	if a.waitFor(done, a.cfg.CommandGrace) {
		return
	}
	a.log.Info("cancelling commands that are still running")
	for _, inFlight := range a.cfg.Executor.InFlight() {
		a.cfg.Executor.Cancel(inFlight.CommandID)
	}
	a.stopRun()
	if !a.waitFor(done, a.cfg.CancelGrace) {
		a.stopPost()
		a.waitFor(done, time.Second)
	}
}

func (a *Agent) waitFor(done <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
