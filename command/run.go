package command

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/orgmio/mio/internal/config"
	"github.com/orgmio/mio/internal/inbound"
	"github.com/orgmio/mio/protocol"
)

func Run(args []string) int {
	if len(args) < 2 {
		usage()
		return 2
	}
	switch args[1] {
	case "run":
		return run(args[2:])
	case "client", "server":
		fmt.Fprintln(os.Stderr, "use: mio run -c config.toml")
		return run(args[2:])
	case "version", "-v", "--version":
		PrintVersion()
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[1])
		usage()
		return 2
	}
}

func run(args []string) int {
	path, err := configPath(args)
	if err != nil {
		if err == errHelp {
			usage()
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	role, err := cfg.Role()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch role {
	case config.RoleClient:
		return runClient(ctx, cfg)
	case config.RoleServer:
		return runServer(ctx, cfg)
	default:
		fmt.Fprintln(os.Stderr, "unknown role")
		return 1
	}
}

func runClient(ctx context.Context, cfg config.File) int {
	clientCfg, err := cfg.ClientConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cli, err := protocol.NewClient(clientCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer cli.Close()

	ln, err := net.Listen("tcp", cfg.SOCKS5Listen())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		cli.Close()
	}()
	slog.Info("socks5 listening", "addr", ln.Addr().String())
	socks := inbound.NewSOCKS5(cli.Dial)
	if err := socks.Serve(ln); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runServer(ctx context.Context, cfg config.File) int {
	serverCfg, err := cfg.ServerConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	srv, err := protocol.NewServer(serverCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	slog.Info("mio server starting", "listen", serverCfg.Addr)
	if err := srv.ListenAndServe(ctx); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func configPath(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a path", args[i])
			}
			return args[i+1], nil
		case "-h", "--help":
			return "", errHelp
		default:
			if len(args[i]) > 0 && args[i][0] == '-' {
				return "", fmt.Errorf("unknown flag %s", args[i])
			}
		}
	}
	return "", fmt.Errorf("missing -c <config.toml>")
}

type helpError struct{}

func (helpError) Error() string { return "help" }

var errHelp = helpError{}
