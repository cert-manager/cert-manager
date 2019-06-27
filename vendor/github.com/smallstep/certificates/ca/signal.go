package ca

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Stopper is the interface that external commands can implement to stop the
// server.
type Stopper interface {
	Stop() error
}

// StopReloader is the interface that external commands can implement to stop
// the server and reload the configuration while running.
type StopReloader interface {
	Stop() error
	Reload() error
}

// StopHandler watches SIGINT, SIGTERM on a list of servers implementing the
// Stopper interface, and when one of those signals is caught we'll run Stop
// (SIGINT, SIGTERM) on all servers.
func StopHandler(servers ...Stopper) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Println("shutting down ...")
				for _, server := range servers {
					err := server.Stop()
					if err != nil {
						log.Printf("error stopping server: %s", err.Error())
					}
				}
				return
			}
		}
	}
}

// StopReloaderHandler watches SIGINT, SIGTERM and SIGHUP on a list of servers
// implementing the StopReloader interface, and when one of those signals is
// caught we'll run Stop (SIGINT, SIGTERM) or Reload (SIGHUP) on all servers.
func StopReloaderHandler(servers ...StopReloader) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				log.Println("reloading ...")
				for _, server := range servers {
					err := server.Reload()
					if err != nil {
						log.Printf("error reloading server: %+v", err)
					}
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.Println("shutting down ...")
				for _, server := range servers {
					err := server.Stop()
					if err != nil {
						log.Printf("error stopping server: %s", err.Error())
					}
				}
				return
			}
		}
	}
}
