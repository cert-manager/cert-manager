package main

import (
	"github.com/etix/stoppableListener"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {

	/* Listen on port 8080 */
	listener, err := net.Listen("tcp", "127.0.0.1:8080")

	log.Println("Server listening on http://127.0.0.1:8080/")

	/* Make the listener stoppable to be able to shutdown the server gracefully */
	stoppable := stoppableListener.Handle(listener)

	/* Handle SIGTERM (Ctrl+C) */
	k := make(chan os.Signal, 1)
	signal.Notify(k, os.Interrupt)
	go func() {
		<-k
		stoppable.Stop <- true
	}()

	/* Our HelloWorld function */
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello World!\n")
		log.Println("Incoming request for", req.URL.Path)
	})

	/* Serve until we receive a SIGTERM */
	err = http.Serve(stoppable, nil)

	/* Check why the Serve loop exited */
	if stoppable.Stopped {
		var alive int

		/* Wait at most 5 seconds for the clients to disconnect */
		for i := 0; i < 5; i++ {
			/* Get the number of clients still connected */
			alive = stoppable.ConnCount.Get()
			if alive == 0 {
				break
			}
			log.Printf("%d client(s) still connected…\n", alive)
			time.Sleep(1 * time.Second)
		}

		alive = stoppable.ConnCount.Get()
		if alive > 0 {
			log.Fatalf("Server stopped after 5 seconds with %d client(s) still connected.", alive)
		} else {
			log.Println("Server stopped gracefully.")
			os.Exit(0)
		}
	} else if err != nil {
		log.Fatal(err)
	}
}
