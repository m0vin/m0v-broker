package main

import (
        "bufio"
        "crypto/rand"
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "expvar"
        "flag"
        "fmt"
        _ "io/ioutil"
        "log"
        "net"
        "net/http"
        "strings"
        _ "strconv"
        "sync"
        "time"
        _"errors"
	"github.com/m0vin/m0v-broker/data"
        "github.com/golang/glog"
)

// Device 'posts' all 3 parameters, app queries with 2 (deviceName, ssid) and gets either a timestamp or a not found.
type Confo struct {
        Devicename string`json:"deviceName"`
        Timestamp int64 `json:"timestamp,omitempty"`
        Ssid string `json:"ssid"`
        Hash int64 `json:"hash,omitempty"`
        Sub string `json:"email,omitempty"`
}
const (
	// Port is the port number that the server listens to.
	Port = ":38979"
        // Root CA
        RootCA = "dst_rootca_x3.pem"
        // Let's Encrypt
        CA = "b00m-trusted-ca-cert.pem"
)
var (
        ch chan *Confo
        oks *expvar.Int
        tlsoks *expvar.Int
        httpRto int
        httpWto int
        httpPort int
        httpsPort int
        local = false
        b00m tls.Certificate
)

// HandleFunc is a function that handles an incoming command.
// It receives the open connection wrapped in a `ReadWriter` interface.
type HandleFunc func(*bufio.ReadWriter)

// Endpoint provides an endpoint to other processess  that they can send data to.
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
        if *secure {
                if local {
                        //cert, err := tls.LoadX509KeyPair("35.197.240.121.cert.pem", "35.197.240.121.key.pem")
                        b00m, err = tls.LoadX509KeyPair("dummy-trusted-cert.pem", "dummy-trusted-cert-key.pem")
                } else {
                        b00m, err = tls.LoadX509KeyPair("b00m-trusted-chain.pem", "b00m-trusted-cert-key.pem")
                }
                if err != nil {
                        return fmt.Errorf("unable to load certs: %v", err)
                }
                //certs = append(certs, cert)
                config := &tls.Config{
                        Certificates: []tls.Certificate{b00m},
                        Rand: rand.Reader,
                        //CipherSuites: []uint16{0xc027},
                        //CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA,
                        //                        tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
                        PreferServerCipherSuites: true,
                        GetCertificate: getClientCert,
                        //RootCAs: dsarootx3,
                }
                log.Println(config.CipherSuites, config.PreferServerCipherSuites)
                e.listener, err = tls.Listen("tcp", Port, config)
                if err != nil {
                        return fmt.Errorf("Unable to listen on "+e.listener.Addr().String() + "%v \n", err)
                }
        } else {
                e.listener, err = net.Listen("tcp", Port)
                if err != nil {
                        return fmt.Errorf("Unable to listen on "+e.listener.Addr().String() + "%v \n", err)
                }

        }
        log.Println("Listen on", e.listener.Addr().String())
        for {
                log.Println("Accept a connection request.")
                conn, err := e.listener.Accept()
                if err != nil {
                        log.Println("Failed accepting a connection request:", err)
                        continue
                }
                log.Printf("server: accepted from %s", conn.RemoteAddr())
                tlscon, ok := conn.(*tls.Conn)
                if ok {
                    log.Println("ok=true")
                    state := tlscon.ConnectionState()
                    log.Println(state)
                    for _, v := range state.PeerCertificates {
                        fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
                    }
                }
                go e.handleMessages(conn)
        }
}

func getClientCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        fmt.Println(hello.CipherSuites)
        fmt.Println(hello.SupportedVersions)
        return nil, nil
}

// handleMessages reads the connection up to the first newline.
// Based on this string, it calls the appropriate HandleFunc.
func (e *Endpoint) handleMessages(conn net.Conn) {
	// Wrap the connection into a buffered reader for easier reading.
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	defer conn.Close()

        /*for {
        bs := make([]byte, 10000)
        n, err := rw.Read(bs)
		switch {
		case err == io.EOF:
			log.Printf("Reached EOF - close this connection. %v %v \n   ---", n, string(bs))
			//log.Println("Reached EOF - close this connection. \n   ---")
			return
		case err != nil:
			log.Println("\nError during handshake: ", err)
			//log.Println("\nError reading command. Got: '"+string(bs)+"'\n", err)
			return
		}
		handleJSON(rw)
                return
        }*/
        handleJSON(rw)
}

// handleJSON attempts to marshal recd. json data into Confo. If successful, tests for number of parameters. If 3 (devicename, ssid, timestamp) then sent by device, so packet is saved in db and response serial id persisted by device for sending with subsequent packets. If 2 (devicename, ssid) then query by app, so check if (devicename,ssid) has an entry in db and respond with the last timestamp for (devicename,ssid).
func handleJSON(rw *bufio.ReadWriter) {
        log.Print("Received JSON data")
        confo := &Confo{}
        dec := json.NewDecoder(rw)
        err := dec.Decode(confo)
        if err != nil {
                log.Println("Error decoding JSON data", err)
                // !OK
                _, err = rw.WriteString("!OK\n")
                if err != nil {
                        log.Println("Cannot write to connection.\n", err)
                }
                err = rw.Flush()
                if err != nil {
                        log.Println("Flush failed.", err)
                }
                return
        }
        log.Printf("Confo: %v \n", confo)
        confo, err = validate(confo)
        if err != nil {
		glog.Infof("Confo invalid %v \n", err)
                // !OK
                _, err = rw.WriteString("!OK\n")
                if err != nil {
                        log.Println("Cannot write to connection.\n", err)
                }
                err = rw.Flush()
                if err != nil {
                        log.Println("Flush failed.", err)
                }
                return
        }
        // OK
	_, err = rw.WriteString("OK.\n")
	if err != nil {
		glog.Errorf("Cannot write to connection %v \n", err)
	}
	err = rw.Flush()
	if err != nil {
		glog.Errorf("Flush failed %v \n", err)
	}
        select {
        case ch<-confo:
        default:
        }
}

func validate(confo *Confo) (*Confo, error) {
        if confo.Devicename == "" || confo.Ssid == "" {
                glog.Infof("Recd. inadequate confo params %s %s \n", confo.Devicename, confo.Ssid)
                return nil, fmt.Errorf("Recd. inadequate confo params %s %s \n", confo.Devicename, confo.Ssid)
        }
        if confo.Timestamp == 0 {
                glog.Infof("Adding timestamp to confo %s %s \n", confo.Devicename, confo.Ssid)
                confo.Timestamp = time.Now().Unix()
                return confo, nil
        }
        return confo, nil
}

// server listens for incoming requests and dispatches them to registered handler functions.
func server() error {
	endpoint := NewEndpoint()

	// Add the handle funcs.
	//endpoint.AddHandleFunc("STRING", handleStrings)
	//endpoint.AddHandleFunc("GOB", handleGob)

	// Start listening.
	return endpoint.Listen()
}

var secure = flag.Bool("secure", false, "If true tls.Listen, else net.Listen")

// Parse flags, start the goroutine that saves to database, start the server.
func main() {
	flag.Parse()

        // Start goroutine which reads confos from buffered channel and writes to database
        go store()

        // Start a http(s) server to respond to queries from app.
        go startHttp()

	// Go into server mode.
	err := server()
	if err != nil {
		log.Println("Error:", fmt.Errorf("%V", err))
	}
	log.Println("Server done.")
}

func serveHttp(w http.ResponseWriter, r *http.Request) {
        glog.Infof("Query: %v \n", r.URL.Path)
	enc := json.NewEncoder(w)
        // get the hash from the url
        toks := strings.Split(r.URL.Path, "/")
        if len(toks) < 3 {
                glog.Errorf("Unknown request path : %v", r.URL.Path)
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Not found"))
                return
        }
        devicename := toks[2] // "Movprov"
        ssid := toks[3] // "M0V"
        //hash, err := strconv.ParseInt(toks[1], 10, 64)
        /*if err != nil {
                //glog.Errorf("Bad hash in request : %v", err)
                glog.Errorf("Not enough data in request : %v", err)
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Not found"))
                return
        }*/
        // check that the hash exists in pub and has sent a recent confo
        /*glog.Infof("Retrieving: %s %s \n", devicename, ssid)
        _, err = data.GetPubByHash(hash)
        if err != nil {
                glog.Errorf("Hash not found: %v", err)
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Not found"))
                return
        }*/
        // confo, err := data.GetLastConfoWithHash(hash)
        confo, err := data.GetLastConfo(devicename, ssid)
        if err != nil {
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Not found"))
                return
        }
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
        if err := enc.Encode(confo); err != nil {
                glog.Errorf("retrieve confo json encode : %v", err)
        }
        return
}

func store() {
        // Just testing database connection
        /*c, err := data.GetCoordinate(1)
        if err != nil {
                glog.Errorf("GetLast %v \n", err)
                return err
        } else {
                glog.Infof("GetCoord %v \n", c)
        }*/

        glog.Infof("%s \n", "Storing ... ")
        for {
                select {
                case p := <-ch:
                        knownsub := true
                        // check if the sub is known, i.e. email is registered
                        s, err := data.GetSubByEmail(p.Sub)
                        if err != nil {
                                // email is unregistered, i.e. not in `sub`
                                knownsub = false
                                glog.Infof("Uknown email in confo %s %v \n", p.Sub, err)
                                // check if it's in `csub` and add it if not. 
                                s, err = data.GetCsubByEmail(p.Sub)
                                if err != nil {
                                        glog.Infof("Unkown email not in csub %s %v adding to csub\n", p.Sub, err)
                                        i, err := data.PutCsub(&data.Sub{Email: p.Sub})
                                        if err != nil {
                                                glog.Infof("Unkown email not added to csub %s %v \n", p.Sub, err)
                                        } else {
                                                glog.Infof("Unkown email added to csub %s %d \n", p.Sub, i)
                                        }
                                } else {
                                        glog.Infof("Unkown email already in csub %s %d \n", p.Sub, s.Id)
                                }
                        }
                        // create the pub if the hash is new
                        pub, err := data.GetPubByHash(p.Hash)
                        if err != nil && s != nil {
                                glog.Infof("New hash %d %v \n", p.Hash, err)
                                p := &data.Pub{Hash: p.Hash, Created: time.Unix(p.Timestamp, 0), Creator: s.Id}
                                i, err := data.PutPub(p)
                                if err != nil {
                                        glog.Infof("Couldn't store new hash %d %v \n", p.Hash, err)
                                } else {
                                        glog.Infof("Pub saved %d %d \n", i, p.Hash)
                                        pub = p
                                }
                        }
                        // pub with hash pre-exists
                        if pub != nil {
                                glog.Infof("Pub exists Id:%d Hash:%d Creator:%d\n", pub.Id, pub.Hash, pub.Creator)
                                if !knownsub { // ensure creator is unpopulated
                                        glog.Infof("Pub hash %d creator %d should be nil \n", pub.Hash, pub.Creator)
                                } else {
                                        if pub.Creator != 0 && pub.Creator != s.Id {
                                                glog.Infof("Conflict! pub hash %d creator %d, new creator %d \n", pub.Hash, pub.Creator, s.Id)
                                        } else { // pub.Creator = 0, i.e. not previously populated even though knownsub and pre-existing hash
                                                pub.Creator = s.Id
                                                if err := data.UpdatePub(pub); err != nil {
                                                        glog.Infof("Couldn't update pub hash %d with creator %d \n", pub.Hash, s.Id)
                                                }
                                        }
                                }
                        }
                        // store the confo anyway
                        dp, err := c2dc(p)
                        if err != nil {
                                glog.Infof("%v \n", err)
                        }
                        i, err := data.PutConfo(dp)
                        if err != nil {
                                glog.Infof("%s %v \n", "Confo not saved: ", err)
                        }
                        glog.Infof("%s %d \n", "Confo saved: %d", i)
                case <-time.After(30*time.Second):
                        glog.Infof("%s \n", "No confo received for 30 seconds")
                }
        }
}

func c2dc(c *Confo) (*data.Confo, error) {
        return &data.Confo{Devicename: c.Devicename, Ssid: c.Ssid, Created: time.Unix(c.Timestamp, 0), Hash: c.Hash}, nil
}

// The Lshortfile flag includes file name and line number in log messages.
func init() {
        ch = make(chan *Confo, 10)
	log.SetFlags(log.Lshortfile)
        oks = expvar.NewInt("oks")
        tlsoks = expvar.NewInt("tlsoks")
        flag.IntVar(&httpRto, "wto", 10, "Read timeout")
        flag.IntVar(&httpWto, "rto", 10, "Write timeout")
        flag.IntVar(&httpPort, "http_port", 38980, "Http server port")
        flag.IntVar(&httpsPort, "https_port", 443, "Http server port")
        flag.BoolVar(&local, "local", false, "Run locally with dummy certs")
}

func startHttp() {
        mux := http.NewServeMux()
        //mux.Handle("/", http.HandlerFunc(RedirectHttp))
        mux.Handle("/confo/", http.HandlerFunc(serveHttp))
        hs := http.Server{
                ReadTimeout: time.Duration(httpRto) * time.Second,
                WriteTimeout: time.Duration(httpWto) * time.Second,
                Addr: fmt.Sprintf(":%d", httpPort),
                Handler: mux,
        }
        err := hs.ListenAndServe()
        if err != nil {
                glog.Errorf("Oops: %v \n", err)
        }
}

func startHttps() {
        mux := http.NewServeMux()
        mux.Handle("/debug/vars", expvar.Handler())
        mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                tlsoks.Add(1)
                fmt.Printf("Secure visitor %s %v \n", r.RemoteAddr, *tlsoks)
                fmt.Fprintf(w, "Secure but nothing to see here \n")
        }))
        hs := http.Server{
                ReadTimeout: time.Duration(httpRto) * time.Second,
                WriteTimeout: time.Duration(httpWto) * time.Second,
                Addr: ":https", //fmt.Sprintf(":%d", httpsPort),
                //TLSConfig: man.TLSConfig(),
                Handler: mux,
        }
        err := hs.ListenAndServeTLS("", "")
        if err != nil {
                fmt.Printf("Https %v \n", err)
                return
        }
}

