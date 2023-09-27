package status

// Status represents the status of an entity, typically used for indicating the state or category of something.
type Status string

const Obsolete Status = "obsolete"
const Permanent Status = "permanent"
const PermanentStandard Status = (Permanent + ":standard")
const Proposed Status = "Proposed"
const Provisional Status = "provisional"
