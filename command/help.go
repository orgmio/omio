package command

import (
	"fmt"
)

func usage() {
	fmt.Printf("Usage: mio <command> [<args>]\n\n")
	fmt.Printf("Commands:                    Introduction:\n")
	fmt.Printf(" mio version                 Show the mio proxy protocol version\n")
	fmt.Printf(" mio run -c <config.toml>    Start the mio proxy protocol\n")
}
