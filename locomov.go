// ## Imports and globals
package main

import (
	"bufio"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

        "fmt"
	_"errors"

	"encoding/gob"
	"encoding/json"
	"flag"
)

// A struct with a mix of fields, used for the GOB example.
type complexData struct {
	N int
	S string
	M map[string]int
	P []byte
	C *complexData
}

type Packet struct {
        Id int64 `json:"id!`
        Timestamp int64 `json:"timestamp,omitempty"`
        Status bool `json:"status"`
        Voltage float64 `json:"voltage"`
        Frequency float64 `json:"freq"`
        Lat float64 `json:"lat"`
        Lng float64 `json:"lng"`
}

const (
	// Port is the port number that the server listens to.
	Port = ":38979"
)

/*
## Outcoing connections

Using an outgoing connection is a snap. A `net.Conn` satisfies the io.Reader
and `io.Writer` interfaces, so we can treat a TCP connection just like any other
`Reader` or `Writer`.
*/

// Open connects to a TCP Address.
// It returns a TCP connection armed with a timeout and wrapped into a
// buffered ReadWriter.
func Open(addr string) (*bufio.ReadWriter, error) {
	// Dial the remote process.
	// Note that the local port is chosen on the fly. If the local port
	// must be a specific one, use DialTCP() instead.
	log.Println("Dial " + addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Dialing "+addr+" failed %v", err)
	}
	return bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

/*
## Incoming connections

Preparing for incoming data is a bit more involved. According to our ad-hoc
protocol, we receive the name of a command terminated by `\n`, followed by data.
The nature of the data depends on the respective command. To handle this, we
create an `Endpoint` object with the following properties:

* It allows to register one or more handler functions, where each can handle a
  particular command.
* It dispatches incoming commands to the associated handler based on the commands
  name.

*/

// HandleFunc is a function that handles an incoming command.
// It receives the open connection wrapped in a `ReadWriter` interface.
type HandleFunc func(*bufio.ReadWriter)

// Endpoint provides an endpoint to other processess
// that they can send data to.
type Endpoint struct {
	listener net.Listener
	handler  map[string]HandleFunc

	// Maps are not threadsafe, so we need a mutex to control access.
	m sync.RWMutex
}

// NewEndpoint creates a new endpoint. Too keep things simple,
// the endpoint listens on a fixed port number.
func NewEndpoint() *Endpoint {
	// Create a new Endpoint with an empty list of handler funcs.
	return &Endpoint{
		handler: map[string]HandleFunc{},
	}
}

// AddHandleFunc adds a new function for handling incoming data.
func (e *Endpoint) AddHandleFunc(name string, f HandleFunc) {
	e.m.Lock()
	e.handler[name] = f
	e.m.Unlock()
}

// Listen starts listening on the endpoint port on all interfaces.
// At least one handler function must have been added
// through AddHandleFunc() before.
func (e *Endpoint) Listen() error {
	var err error
	e.listener, err = net.Listen("tcp", Port)
	if err != nil {
		return fmt.Errorf("Unable to listen on "+e.listener.Addr().String() + "%v \n", err)
	}
	log.Println("Listen on", e.listener.Addr().String())
	for {
		log.Println("Accept a connection request.")
		conn, err := e.listener.Accept()
		if err != nil {
			log.Println("Failed accepting a connection request:", err)
			continue
		}
		log.Println("Handle incoming messages.")
		go e.handleMessages(conn)
	}
}

// handleMessages reads the connection up to the first newline.
// Based on this string, it calls the appropriate HandleFunc.
func (e *Endpoint) handleMessages(conn net.Conn) {
	// Wrap the connection into a buffered reader for easier reading.
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	defer conn.Close()

        handleJSON(rw)
}

/* Now let's create two handler functions. The easiest case is where our
ad-hoc protocol only sends string data.

The second handler receives and processes a struct that was send as GOB data.
*/

// handleStrings handles the "STRING" request.
func handleStrings(rw *bufio.ReadWriter) {
	// Receive a string.
	log.Print("Receive STRING message:")
	s, err := rw.ReadString('\n')
	if err != nil {
		log.Println("Cannot read from connection.\n", err)
	}
	s = strings.Trim(s, "\n ")
	log.Println(s)
	_, err = rw.WriteString("Thank you.\n")
	if err != nil {
		log.Println("Cannot write to connection.\n", err)
	}
	err = rw.Flush()
	if err != nil {
		log.Println("Flush failed.", err)
	}
}

// handleGob handles the "GOB" request. It decodes the received GOB data
// into a struct.
func handleGob(rw *bufio.ReadWriter) {
	log.Print("Receive GOB data:")
	var data complexData
	// Create a decoder that decodes directly into a struct variable.
	dec := gob.NewDecoder(rw)
	err := dec.Decode(&data)
	if err != nil {
		log.Println("Error decoding GOB data:", err)
		return
	}
	// Print the complexData struct and the nested one, too, to prove
	// that both travelled across the wire.
	log.Printf("Outer complexData struct: \n%#v\n", data)
	log.Printf("Inner complexData struct: \n%#v\n", data.C)
}

// handleJSON
func handleJSON(rw *bufio.ReadWriter) {
        log.Print("Received JSON data")
        packet := &Packet{}
        dec := json.NewDecoder(rw)
        err := dec.Decode(packet)
        if err != nil {
                log.Println("Error decoding JSON data", err)
                return
        }
        log.Printf("Packet: %v \n", packet)
	_, err = rw.WriteString("Thank you.\n")
	if err != nil {
		log.Println("Cannot write to connection.\n", err)
	}
	err = rw.Flush()
	if err != nil {
		log.Println("Flush failed.", err)
	}
}

/*
## The client and server functions

With all this in place, we can now set up client and server functions.

The client function connects to the server and sends STRING and GOB requests.

The server starts listening for requests and triggers the appropriate handlers.
*/

// client is called if the app is called with -connect=`ip addr`.
func client(ip string) error {
	// Some test data. Note how GOB even handles maps, slices, and
	// recursive data structures without problems.
	testStruct := complexData{
		N: 23,
		S: "string data",
		M: map[string]int{"one": 1, "two": 2, "three": 3},
		P: []byte("abc"),
		C: &complexData{
			N: 256,
			S: "Recursive structs? Piece of cake!",
			M: map[string]int{"01": 1, "10": 2, "11": 3},
		},
	}

	// Open a connection to the server.
	rw, err := Open(ip + Port)
	if err != nil {
		return fmt.Errorf("Client: Failed to open connection to %v %v %v", ip, Port, err)
	}

	// Send a STRING request.
	// Send the request name.
	// Send the data.
	log.Println("Send the string request.")
	n, err := rw.WriteString("STRING\n")
	if err != nil {
		return fmt.Errorf("Could not send the STRING request ("+strconv.Itoa(n)+" bytes written) %v", err)
	}
	n, err = rw.WriteString("Additional data.\n")
	if err != nil {
		return fmt.Errorf("Could not send additional STRING data ("+strconv.Itoa(n)+" bytes written) %v", err)
	}
	log.Println("Flush the buffer.")
	err = rw.Flush()
	if err != nil {
		return fmt.Errorf("Flush failed. %v", err)
	}

	// Read the reply.
	log.Println("Read the reply.")
	response, err := rw.ReadString('\n')
	if err != nil {
		return fmt.Errorf("Client: Failed to read the reply: %v %v", response, err)
	}

	log.Println("STRING request: got a response:", response)

	// Send a GOB request.
	// Create an encoder that directly transmits to `rw`.
	// Send the request name.
	// Send the GOB.
	log.Println("Send a struct as GOB:")
	log.Printf("Outer complexData struct: \n%#v\n", testStruct)
	log.Printf("Inner complexData struct: \n%#v\n", testStruct.C)
	enc := gob.NewEncoder(rw)
	n, err = rw.WriteString("GOB\n")
	if err != nil {
		return fmt.Errorf("Could not write GOB data ("+strconv.Itoa(n)+" bytes written) %v", err)
	}
	err = enc.Encode(testStruct)
	if err != nil {
		return fmt.Errorf("Encode failed for struct: %#v %v", testStruct, err)
	}
	err = rw.Flush()
	if err != nil {
		return fmt.Errorf("Flush failed. %v", err)
	}
	return nil
}

// server listens for incoming requests and dispatches them to
// registered handler functions.
func server() error {
	endpoint := NewEndpoint()

	// Add the handle funcs.
	endpoint.AddHandleFunc("STRING", handleStrings)
	endpoint.AddHandleFunc("GOB", handleGob)

	// Start listening.
	return endpoint.Listen()
}

/*
## Main

Main starts either a client or a server, depending on whether the `connect`
flag is set. Without the flag, the process starts as a server, listening
for incoming requests. With the flag the process starts as a client and connects
to the host specified by the flag value.

Try "localhost" or "127.0.0.1" when running both processes on the same machine.

*/

// main
func main() {
	connect := flag.String("connect", "", "IP address of process to join. If empty, go into listen mode.")
	flag.Parse()

	// If the connect flag is set, go into client mode.
	if *connect != "" {
		err := client(*connect)
		if err != nil {
			log.Println("Error:", fmt.Errorf("%v", err))
		}
		log.Println("Client done.")
		return
	}

	// Else go into server mode.
	err := server()
	if err != nil {
		log.Println("Error:", fmt.Errorf("%V", err))
	}

	log.Println("Server done.")
}

// The Lshortfile flag includes file name and line number in log messages.
func init() {
	log.SetFlags(log.Lshortfile)
}

/*
## How to get and run the code

Step 1: `go get` the code. Note the `-d` flag that prevents auto-installing
the binary into `$GOPATH/bin`.

    go get -d github.com/appliedgo/networking

Step 2: `cd` to the source code directory.

    cd $GOPATH/src/github.com/appliedgo/networking

Step 3. Run the server.

    go run networking.go

Step 4. Open another shell, `cd` to the source code (see Step 2), and
run the client.

    go run networking.go -connect localhost


## Tips

If you want to tinker with the code a bit, here are some suggestions:

* Try running client and server on different machines (in the same local network).
* Beef up the complexData type with more maps and pointers and see how `gob`
  copes with it.
* Start several clients at the same time and see if the server can handle them.


## Links

This turned into quite a long blog post, so if you are looking for something
shorter, here is a blog post that is really just the essence of the above, and
it is just sending strings. No gobs, and no fancy "command/data" constructs.

* [A Simple Go TCP Server and TCP Client](https://systembash.com/a-simple-go-tcp-server-and-tcp-client/)

More about the `gob` package:

* [Gobs of data](https://blog.golang.org/gobs-of-data)

**Happy coding!**

- - -

Errata

2017-02-09 - Map access: Maps are not thread-safe and thus if a map is used in
different goroutines, a mutex should always control access to a map. In the given code, the map is updated before the goroutine starts, so mutexes were not necessary. Nevertheless, I now added one, so you can now safely modify the code and call AddHandleFunc() while the handleMessages goroutine is already running.

*/
