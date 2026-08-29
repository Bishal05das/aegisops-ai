package agent

import (
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// TaskStatus is the lifecycle of one unit of agent work.
type TaskStatus string

// Task lifecycle states.
const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskSucceeded TaskStatus = "succeeded"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
	TaskTimedOut  TaskStatus = "timed_out"
)

// taskTransitions is the allowed state graph.
var taskTransitions = map[TaskStatus][]TaskStatus{
	TaskPending: {TaskRunning, TaskCancelled},
	TaskRunning: {TaskSucceeded, TaskFailed, TaskCancelled, TaskTimedOut},
	// Terminal states. A retry creates a new task rather than resurrecting one,
	// so each attempt keeps its own record — which is what makes "this agent
	// failed twice before succeeding" visible in a postmortem.
	TaskSucceeded: {},
	TaskFailed:    {},
	TaskCancelled: {},
	TaskTimedOut:  {},
}

// Valid reports whether the status is defined.
func (s TaskStatus) Valid() bool {
	_, ok := taskTransitions[s]
	return ok
}

// Terminal reports whether the task has finished, however it finished.
func (s TaskStatus) Terminal() bool { return len(taskTransitions[s]) == 0 }

// CanTransitionTo reports whether moving to next is permitted.
func (s TaskStatus) CanTransitionTo(next TaskStatus) bool {
	for _, allowed := range taskTransitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Task is one unit of work dispatched to an agent.
type Task struct {
	ID         shared.ID
	IncidentID shared.ID
	AgentID    ID

	// ParentID chains a task to the one that spawned it, so the Incident
	// Manager's plan and the sub-tasks it fanned out form a readable tree.
	ParentID *shared.ID

	Type   string
	Status TaskStatus

	Input  map[string]any
	Output map[string]any
	Error  string

	// Attempts counts executions of this logical step. The harness uses it with
	// errs.Retryable to decide between backing off and dead-lettering.
	Attempts int

	StartedAt  *time.Time
	FinishedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// MaxTaskTypeLen bounds the task type discriminator.
const MaxTaskTypeLen = 100

// NewTask builds a validated pending task.
func NewTask(clock shared.Clock, incidentID, agentID shared.ID, taskType string) (*Task, error) {
	now := clock.Now()
	t := &Task{
		ID:         shared.NewID(),
		IncidentID: incidentID,
		AgentID:    agentID,
		Type:       taskType,
		Status:     TaskPending,
		Input:      map[string]any{},
		Output:     map[string]any{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}

// Validate checks the task's invariants.
func (t *Task) Validate() error {
	v := shared.NewValidator("agent_task")
	v.NotZeroID(t.ID, "id")
	v.NotZeroID(t.IncidentID, "incident_id")
	v.NotZeroID(t.AgentID, "agent_id")
	v.Required(t.Type, "type")
	v.MaxLen(t.Type, "type", MaxTaskTypeLen)
	v.Check(t.Status.Valid(), "status", "is not a known task state")
	v.Check(t.Attempts >= 0, "attempts", "cannot be negative")
	return v.Err()
}

// Start moves the task to running and stamps the start time.
func (t *Task) Start(clock shared.Clock) error {
	if err := t.transition(clock, TaskRunning); err != nil {
		return err
	}
	now := clock.Now()
	if t.StartedAt == nil {
		t.StartedAt = &now
	}
	t.Attempts++
	return nil
}

// Succeed records a successful completion and its output.
func (t *Task) Succeed(clock shared.Clock, output map[string]any) error {
	if err := t.transition(clock, TaskSucceeded); err != nil {
		return err
	}
	t.Output = output
	t.finish(clock)
	return nil
}

// Fail records a failure and its reason.
func (t *Task) Fail(clock shared.Clock, reason string) error {
	if err := t.transition(clock, TaskFailed); err != nil {
		return err
	}
	t.Error = reason
	t.finish(clock)
	return nil
}

// TimeOut records that the task exceeded its deadline.
func (t *Task) TimeOut(clock shared.Clock) error {
	if err := t.transition(clock, TaskTimedOut); err != nil {
		return err
	}
	t.Error = "task exceeded its deadline"
	t.finish(clock)
	return nil
}

// Cancel records that the task was abandoned, usually because the incident it
// belonged to was resolved by another path.
func (t *Task) Cancel(clock shared.Clock, reason string) error {
	if err := t.transition(clock, TaskCancelled); err != nil {
		return err
	}
	t.Error = reason
	t.finish(clock)
	return nil
}

// Duration reports how long the task ran, or false if it has not finished.
func (t *Task) Duration() (time.Duration, bool) {
	if t.StartedAt == nil || t.FinishedAt == nil {
		return 0, false
	}
	return t.FinishedAt.Sub(*t.StartedAt), true
}

func (t *Task) transition(clock shared.Clock, next TaskStatus) error {
	if t.Status == next {
		return nil // idempotent
	}
	if !t.Status.CanTransitionTo(next) {
		return fmt.Errorf("%w: cannot move task from %s to %s",
			shared.ErrConflict, t.Status, next)
	}
	t.Status = next
	t.UpdatedAt = clock.Now()
	return nil
}

func (t *Task) finish(clock shared.Clock) {
	now := clock.Now()
	if t.FinishedAt == nil {
		t.FinishedAt = &now
	}
}
