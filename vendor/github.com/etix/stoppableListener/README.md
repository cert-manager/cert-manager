# stoppableListener

[![Build Status](https://travis-ci.org/etix/stoppableListener.png?branch=master)](https://travis-ci.org/etix/stoppableListener)

A Go helper package to gracefully stop a net/http server.

### Basic Usage

```go
import "github.com/etix/stoppableListener"

func main() {
    listener, err := net.Listen("tcp", "127.0.0.1:8080")

    stoppable := stoppableListener.Handle(listener)

    /* Handle SIGTERM (Ctrl+C) */
    k := make(chan os.Signal, 1)
    signal.Notify(k, os.Interrupt)
    go func() {
        <-k
        stoppable.Stop <- true
    }()

    http.Serve(stoppable, nil)
}

```

See the [example](https://github.com/etix/stoppableListener/tree/master/example) folder for a fully working example.

### Installation

The usual. `go get github.com/etix/stoppableListener`

### Documentation

For details on this package, see [GoDoc](http://godoc.org/github.com/etix/stoppableListener).

### License

The MIT License (MIT)

Copyright (c) 2013 Ludovic Fauvet

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

