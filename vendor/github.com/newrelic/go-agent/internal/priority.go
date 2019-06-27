package internal

// Priority allows for a priority sampling of events.  When an event
// is created it is given a Priority.  Whenever an event pool is
// full and events need to be dropped, the events with the lowest priority
// are dropped.
type Priority float32

// According to spec, Agents SHOULD truncate the value to at most 6
// digits past the decimal point.
const (
	priorityFormat = "%.6f"
)

// NewPriority returns a new priority.
func NewPriority() Priority {
	return Priority(RandFloat32())
}

// Float32 returns the priority as a float32.
func (p Priority) Float32() float32 {
	return float32(p)
}

func (p Priority) isLowerPriority(y Priority) bool {
	return p < y
}
