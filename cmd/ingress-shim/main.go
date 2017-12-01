package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/logs"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()
	stopCh := SetupSignalHandler()

	cmd := NewCommandStartController(stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)
	flag.CommandLine.Parse([]string{})
	if err := cmd.Execute(); err != nil {
		glog.Fatal(err)
	}
}

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
var onlyOneSignalHandler = make(chan struct{})

// SetupSignalHandler registered for SIGTERM and SIGINT. A stop channel is returned
// which is closed on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func SetupSignalHandler() (stopCh <-chan struct{}) {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}
