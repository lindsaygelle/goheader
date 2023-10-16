package name_test

import (
	"fmt"

	"github.com/lindsaygelle/goheader/name"
)

func ExampleNew() {
	newName := name.New("X-New-Name")
	fmt.Printf("HTTP Header Name %s", newName)
}
