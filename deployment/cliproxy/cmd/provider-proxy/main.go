package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	runtimehost "github.com/artex/cliproxyhost/internal/runtime"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("provider-proxy", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8788", "loopback HTTP listen address")
	data := flags.String("data", "", "private native proxy state root")
	tokenFile := flags.String("token-file", "", "bearer capability file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *data == "" || *tokenFile == "" {
		return errors.New("-data and -token-file are required")
	}
	if err := validateListenAddress(*listen); err != nil {
		return err
	}
	token, err := readBearerCapability(*tokenFile)
	if err != nil {
		return err
	}
	defer clear(token)
	app, err := runtimehost.New(*data, token)
	if err != nil {
		return err
	}
	return serve(*listen, app.HTTPHandler())
}

func readBearerCapability(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not read bearer capability file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("bearer capability must be a private regular file")
	}
	token, err := io.ReadAll(f)
	if err != nil {
		return nil, errors.New("could not read bearer capability file")
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 {
		return nil, errors.New("bearer capability file is empty")
	}
	return token, nil
}

func validateListenAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("listen address must be a loopback host and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must use a loopback IP")
	}
	return nil
}

func serve(addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
		return nil
	}
}
