// Package status defines a custom Status type and constants representing various entity statuses.
package status

// Status represents the status of an entity, typically used for indicating the state or category of something.
type Status string

// Obsolete is a constant representing an entity with an "obsolete" status.
const Obsolete Status = "obsolete"

// Permanent is a constant representing an entity with a "permanent" status.
const Permanent Status = "permanent"

// PermanentStandard is a constant representing an entity with a "permanent:standard" status.
const PermanentStandard Status = (Permanent + ":standard")

// Proposed is a constant representing an entity with a "Proposed" status.
const Proposed Status = "Proposed"

// Provisional is a constant representing an entity with a "provisional" status.
const Provisional Status = "provisional"