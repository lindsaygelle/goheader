package status_test

import (
	"fmt"

	"github.com/lindsaygelle/goheader/status"
)

func ExampleNew() {
	newStatus := status.New("Working")
	fmt.Printf("HTTP Header Status %s", newStatus)
}
