package recovery

import "fmt"

// UnsupportedResourceTypeError is returned when disaster recovery attempts to restore
// an unsupported or unhandled workload/engine resource type. Fails closed.
type UnsupportedResourceTypeError struct {
	ResourceType string
	ResourceID   string
}

// Error returns a formatted error string identifying the unsupported resource.
func (e *UnsupportedResourceTypeError) Error() string {
	return fmt.Sprintf("unsupported resource type for disaster recovery restore: %q (resource_id: %s)", e.ResourceType, e.ResourceID)
}
