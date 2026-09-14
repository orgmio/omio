package main

import (
	"log/slog"
	"os"

	"github.com/orgmio/mio/command"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	os.Exit(command.Run(os.Args))
}
