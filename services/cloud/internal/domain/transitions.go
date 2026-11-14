package domain

import "github.com/commonvtake/parallelf/pkg/cloudagent"

// Transition is the result of applying an agent's observation.
type Transition struct {
	State              string
	Message            string
	ObservedGeneration int64
}

// Changed reports whether the transition differs from w.
func (t Transition) Changed(w Workload) bool {
	return t.State != w.State || t.Message != w.StatusMessage || t.ObservedGeneration != w.ObservedGeneration
}

// Observe computes the workload's next state from what its node reports.
//
// The desired state decides how an observation is read: "stopped" is the
// goal for a workload that should be stopped but progress toward running
// for one that should run. A nil observation means the agent said nothing
// about the workload; nothing changes.
func Observe(w Workload, obs *cloudagent.ObservedWorkload) Transition {
	t := Transition{State: w.State, Message: w.StatusMessage, ObservedGeneration: w.ObservedGeneration}
	if obs == nil {
		return t
	}
	if obs.AppliedGeneration > t.ObservedGeneration {
		t.ObservedGeneration = obs.AppliedGeneration
	}
	// A failure of an older generation was answered by a newer request
	// (typically retry) that the agent has not seen yet: it says nothing
	// about the new attempt.
	if obs.State == cloudagent.ObservedError && obs.Generation != 0 && obs.Generation < w.Generation {
		return t
	}
	applied := obs.AppliedGeneration >= w.Generation

	switch w.DesiredState {
	case DesiredDeleted:
		if obs.State == cloudagent.ObservedAbsent {
			t.State, t.Message = StateDeleted, ""
		} else {
			t.State, t.Message = StateDeleting, obs.Message
		}
	case DesiredRunning:
		switch obs.State {
		case cloudagent.ObservedRunning:
			if applied {
				t.State, t.Message = StateRunning, ""
			} else {
				t.State, t.Message = StateProvisioning, obs.Message
			}
		case cloudagent.ObservedError:
			t.State, t.Message = StateError, obs.Message
		case cloudagent.ObservedAbsent:
			// Not created yet: the agent creates it on this sync.
			if w.State != StateScheduled {
				t.State = StateProvisioning
			}
			t.Message = obs.Message
		default: // provisioning, stopping, stopped: on the way to running
			t.State, t.Message = StateProvisioning, obs.Message
		}
	case DesiredStopped:
		switch obs.State {
		case cloudagent.ObservedStopped, cloudagent.ObservedAbsent:
			if applied {
				t.State, t.Message = StateStopped, ""
			} else {
				t.State, t.Message = StateStopping, obs.Message
			}
		case cloudagent.ObservedError:
			t.State, t.Message = StateError, obs.Message
		default:
			t.State, t.Message = StateStopping, obs.Message
		}
	}
	return t
}

// CanStart reports whether a start request is accepted in state.
func CanStart(w Workload) bool {
	if w.NodeID == "" || w.DesiredState == DesiredDeleted {
		return false
	}
	switch w.State {
	case StateStopped, StateStopping, StateError, StateUnknown:
		return true
	}
	return false
}

// CanStop reports whether a stop request is accepted in state.
func CanStop(w Workload) bool {
	if w.NodeID == "" || w.DesiredState != DesiredRunning {
		return false
	}
	switch w.State {
	case StateRunning, StateProvisioning, StateScheduled, StateError, StateUnknown:
		return true
	}
	return false
}
