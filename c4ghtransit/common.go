package c4ghtransit

import (
	"fmt"
)

// We need our custom regex to match all possible container names
// forbid !"#$%&'()*+,/:;<=>?@[\]^`{|}~  allow .-_
func GenericContainerNameRegex(name string) string {
	return fmt.Sprintf("(?P<%s>([^!-,^/^:-@^\\[-\\^^`^\\{-~]+))", name)
}
