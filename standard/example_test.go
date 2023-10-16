package standard_test

import (
	"fmt"

	"github.com/lindsaygelle/goheader/standard"
)

func ExampleNew() {
	newStandard := standard.New(0)
	fmt.Printf("HTTP Header Standard %d", newStandard)
}
