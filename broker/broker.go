package broker

import (
        "bufio"
	"crypto/tls"
        "crypto/rand"
        "crypto/x509"
        "encoding/json"
	"fmt"
        "log"
        "net"
        "net/http"
        "strconv"
        "strings"
        "time"
        "github.com/m0vin/m0v-broker/data"
)

// Device 'posts' all 3 parameters, app queries with 2 (deviceName, ssid) and gets either a timestamp or a not found.
type Confo struct {
        Devicename string`json:"deviceName"`
        Timestamp int64 `json:"timestamp,omitempty"`
        Ssid string `json:"ssid"`
        Hash int64 `json:"hash,omitempty"`
        Sub string `json:"email,omitempty"`
        Coords string `json:"coords,omitempty"`
        Lng float64
        Lat float64
}

// Packet encapsulates the data received from the device.
type Packet struct {
        Id int64 `json:"id"`
        Timestamp int64 `json:"timestamp,omitempty"`
        Timestr string `json:"timestr,omitempty"`
        Status bool `json:"status"`
        Voltage float64 `json:"voltage"`
        Current float64 `json:"current"`
        ActiPwr float64 `json:"activePower"`
        AppaPwr float64 `json:"apparentPwr"`
        ReacPwr float64 `json:"reactivePwr"`
        PwrFctr float64 `json:"powerFactor"`
        Frequency float64 `json:"freq"`
        ImActEn float64 `json:"impActvEnrg"`
        ExActEn float64 `json:"expActvEnrg"`
        ImRctEn float64 `json:"impRctvEnrg"`
        ExRctEn float64 `json:"expRctvEnrg"`
        TlActEn float64 `json:"ttlActvEnrg"`
        TlRctEn float64 `json:"ttlRctvEnrg"`
        Lat float64 `json:"lat"`
        Lng float64 `json:"lng"`
}

type Broker struct {
        config *Config
        tlsConfig *tls.Config
        ch chan *Packet
        chc chan *Confo
        db bool
}

func NewBroker(config *Config) (*Broker, error) {
        if config == nil {
                config = DefaultConfig
        }

        var b00m tls.Certificate
        var err error
        var tlsConfig *tls.Config
        if config.TlsPort != "" {
                if config.TlsInfo.CertFile == "" {
                        b00m, err = tls.LoadX509KeyPair("dummy-trusted-cert.pem", "dummy-trusted-cert-key.pem")
                        if err != nil {
                                fmt.Printf("unable to load certs: %v", err)
                        }
                } else {
                        b00m, err = tls.LoadX509KeyPair(config.TlsInfo.CertFile, config.TlsInfo.KeyFile)

                }
                tlsConfig = &tls.Config{
                        Certificates: []tls.Certificate{b00m},
                        Rand: rand.Reader,
                        CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA},
                        //PreferServerCipherSuites: true,
                        GetCertificate: getClientCert,
                        //RootCAs: dsarootx3,
                }
        }

        ch := make(chan *Packet, 20)
        chc := make(chan *Confo, 10)
        b := &Broker {
                config: config,
                tlsConfig: tlsConfig,
                ch: ch,
                chc: chc,
        }

        if config.Db.Name != "" {
                b.db = true
        }

        return b, err
}

// Start kicks off the listeners for Packets/Confos and validation/storage goroutines based on config input
func (b *Broker) Start() {
        if b == nil {
                fmt.Println("Broker is nil")
                return
        }
        if b.config.Port != "" {
                go b.StartListening(false)
        }

        if b.config.TlsPort != "" {
                go b.StartListening(true)
        }

        if b.config.Db.Name != "" {
                go b.store()
        }

        if b.config.TlsConfoPort != "" {
                go b.StartListeningForConfos(true)
        }

        if b.config.HTTPPort != "" {
                //go b.startHttp() // deprecated
        }
}

// StartListening starts a net.Listener, accepts connection and starts a goroutine to handle each connection. 
func (b *Broker) StartListening(Tls bool) {
        var err error
        var l net.Listener
        if Tls {
                hp := b.config.TlsHost + ":" +  b.config.TlsPort
                l, err = tls.Listen("tcp", hp, b.tlsConfig)
                if err != nil {
                        fmt.Printf("Unable to listen on "+ b.config.TlsPort + " %v \n", err)
                        fmt.Printf("Unable to listen on "+l.Addr().String() + "%v \n", err)
                }
        } else {
                hp := b.config.Host + ":" +  b.config.Port
                l, err = net.Listen("tcp", hp)
                if err != nil {
                        fmt.Printf("Unable to listen on "+ b.config.Port + " %v \n", err)
                        fmt.Printf("Unable to listen on "+l.Addr().String() + "%v \n", err)
                }
        }
        fmt.Printf("Listen on %s for packets \n", l.Addr().String())
        for {
                conn, err := l.Accept()
                if err != nil {
                        fmt.Println("Failed accepting a connection request:", err)
                        continue
                }
                fmt.Println("Handle incoming messages.")
                fmt.Println("tls.Client")
                fmt.Printf("server: accepted from %s", conn.RemoteAddr())
                tlscon, ok := conn.(*tls.Conn)
                if ok {
                    fmt.Println("ok=true")
                    state := tlscon.ConnectionState()
                    fmt.Println(state)
                    for _, v := range state.PeerCertificates {
                        fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
                    }
                }
                go b.handleConnection(conn)
        }
}

// handleConnection wraps the net.Conn with a buffered Reader and depending on the port of the conn.LocalAddr delegates handling as either Confo or Packet. Closes the connection onces done.
func (b *Broker) handleConnection(conn net.Conn) {
	// Wrap the connection into a buffered reader for easier reading.
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	defer conn.Close()
        if strings.Contains(conn.LocalAddr().String(), b.config.TlsConfoPort) {
                b.handleConfo(rw)
        } else {
                b.handlePacket(rw)
        }
}

// handlePacket is the handler for Packet arriving on TlsPort
func (b *Broker) handlePacket(rw *bufio.ReadWriter) {
        fmt.Print("Received JSON data")
        packet := &Packet{}
        dec := json.NewDecoder(rw)
        err := dec.Decode(packet)
        if err != nil {
                fmt.Println("Error decoding JSON data", err)
                return
        }
        fmt.Printf("Packet: %v \n", packet)
	_, err = rw.WriteString("Thank you.\n")
	if err != nil {
		fmt.Println("Cannot write to connection.\n", err)
	}
	err = rw.Flush()
	if err != nil {
		fmt.Println("Flush failed.", err)
	}
        select {
        case b.ch<-packet:
        default:
        }
}

// store is designed to run as a goroutine. It reads from the Packet and Confo channels, further validates and stores the Packet/Confo.
func (b *Broker) store() {
        fmt.Printf("%s \n", "Storing ... ")
        for {
                select {
                case p := <-b.ch:
                        if b.db {
                                dp, err := p2pp(p)
                                if err != nil {
                                        fmt.Printf("%v \n", err)
                                }
                                i, err := data.PutPacket(dp)
                                if err != nil {
                                        fmt.Printf("%s %v \n", "Packet not saved: ", err)
                                }
                                fmt.Printf("%s %d \n", "Packet saved: ", i)
                        }
                case c := <-b.chc:
                        if b.db {
                                knownsub := true
                                // check if the sub is known, i.e. email is registered
                                s, err := data.GetSubByEmail(c.Sub)
                                if err != nil {
                                        // email is unregistered, i.e. not in table `sub`
                                        knownsub = false
                                        log.Printf("Uknown email in confo %s %v \n", c.Sub, err)
                                        // check if it's in `csub` and if not, add it. 
                                        s, err = data.GetCsubByEmail(c.Sub)
                                        if err != nil {
                                                log.Printf("Unkown email not in csub %s %v adding to csub\n", c.Sub, err)
                                                i, err := data.PutCsub(&data.Sub{Email: c.Sub})
                                                if err != nil {
                                                        log.Printf("Unkown email not added to csub %s %v \n", c.Sub, err)
                                                } else {
                                                        log.Printf("Unkown email added to csub %s %d \n", c.Sub, i)
                                                }
                                        } else {
                                                log.Printf("Unkown email already in csub %s %d \n", c.Sub, s.Id)
                                        }
                                }
                                // create the pub if the hash is new, non-zero and sub is known
                                pub, err := data.GetPubByHash(c.Hash)
                                if err != nil && s != nil && knownsub && c.Hash != 0 {
                                        log.Printf("New hash %d %v \n", c.Hash, err)
                                        p := &data.Pub{Hash: c.Hash, Created: time.Unix(c.Timestamp, 0), Creator: s.Id, Longitude: float32(c.Lng), Latitude: float32(c.Lat)}
                                        i, err := data.PutPub(p)
                                        if err != nil {
                                                log.Printf("Couldn't store new hash %d %v \n", c.Hash, err)
                                        } else {
                                                log.Printf("Pub saved %d %d \n", i, p.Hash)
                                                _, err := data.PutPubForSub(int(s.Id),int(i))
                                                if err != nil {
                                                        log.Printf("subpub not populated %v \n", err)
                                                } else {
                                                        log.Printf("Pub %d saved for Sub %d \n", i, s.Id)
                                                }
                                                pub = p
                                        }
                                }
                                // pub with hash pre-exists
                                if pub != nil {
                                        log.Printf("Pub exists Id:%d Hash:%d Creator:%d\n", pub.Id, pub.Hash, pub.Creator)
                                        if !knownsub { // ensure creator is unpopulated
                                                log.Printf("Pub hash %d creator %d should be nil \n", pub.Hash, pub.Creator)
                                        } else {
                                                if pub.Creator != 0 && pub.Creator != s.Id {
                                                        log.Printf("Conflict! pub hash %d creator %d, new creator %d \n", pub.Hash, pub.Creator, s.Id)
                                                } else { // pub.Creator = 0, i.e. not previously populated even though knownsub and pre-existing hash
                                                        pub.Creator = s.Id
                                                        if err := data.UpdatePub(pub); err != nil {
                                                                log.Printf("Couldn't update pub hash %d with creator %d \n", pub.Hash, s.Id)
                                                        }
                                                }
                                        }
                                }
                                // store the confo anyway
                                dp, err := c2dc(c)
                                if err != nil {
                                        log.Printf("%v \n", err)
                                }
                                i, err := data.PutConfo(dp)
                                if err != nil {
                                        log.Printf("%s %v \n", "Confo not saved: ", err)
                                }
                                log.Printf("%s %d \n", "Confo saved: %d", i)
                        }
                case <-time.After(60*time.Second):
                        fmt.Printf("%s \n", "No packets received for 60 seconds")
                }
        }
}

func p2pp(p *Packet) (*data.Packet, error) {
        t, err := time.Parse(time.RFC3339, p.Timestr)
        if err != nil {
                fmt.Printf("Couldn't parse: %s", p.Timestr)
                t = time.Unix(p.Timestamp, 0)
        }
        return &data.Packet{Id: p.Id, Timestamp: t, Status: p.Status, Voltage: p.Voltage, Frequency: p.Frequency, Current: p.Current, ActiPwr: p.ActiPwr, AppaPwr: p.AppaPwr, ReacPwr: p.ReacPwr, PwrFctr: p.PwrFctr, ImActEn: p.ImActEn, ExActEn: p.ExActEn, ImRctEn: p.ImRctEn, ExRctEn: p.ExRctEn, TlActEn: p.TlActEn, TlRctEn: p.TlRctEn, Lat: p.Lat, Lng: p.Lng}, nil
}

func c2dc(c *Confo) (*data.Confo, error) {
        return &data.Confo{Devicename: c.Devicename, Ssid: c.Ssid, Created: time.Unix(c.Timestamp, 0), Hash: c.Hash}, nil
}

// StartListeningForConfos starts a net.Listener, accepts connection and starts a goroutine to handle each connection. 
func (b *Broker) StartListeningForConfos(Tls bool) {
        var err error
        var l net.Listener
        if Tls {
                hp := b.config.TlsHost + ":" +  b.config.TlsConfoPort
                l, err = tls.Listen("tcp", hp, b.tlsConfig)
                if err != nil {
                        fmt.Printf("Unable to listen on "+ b.config.TlsConfoPort + " %v \n", err)
                        fmt.Printf("Unable to listen on "+l.Addr().String() + "%v \n", err)
                }
        } else {
                hp := b.config.Host + ":" +  b.config.Port
                l, err = net.Listen("tcp", hp)
                if err != nil {
                        fmt.Printf("Unable to listen on "+ b.config.Port + " %v \n", err)
                        fmt.Printf("Unable to listen on "+l.Addr().String() + "%v \n", err)
                }
        }
        fmt.Printf("Listen on %s for confos \n", l.Addr().String())
        for {
                conn, err := l.Accept()
                if err != nil {
                        fmt.Println("Failed accepting a connection request:", err)
                        continue
                }
                fmt.Println("Handle incoming messages.")
                fmt.Println("tls.Client")
                fmt.Printf("server: accepted from %s", conn.RemoteAddr())
                tlscon, ok := conn.(*tls.Conn)
                if ok {
                    fmt.Println("ok=true")
                    state := tlscon.ConnectionState()
                    fmt.Println(state)
                    for _, v := range state.PeerCertificates {
                        fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
                    }
                }
                go b.handleConnection(conn)
        }
}

// handleConfo is the handler for Confos arriving on TlsConfoPort. It attempts to marshal recd. json data into Confo. If successful, superficially validates parameters of Confo. If Devicename & Ssid present, Confo is pushed into channel for further validation and storage. Timestamp and Coords are populated if absent in Confo.
func (b *Broker) handleConfo(rw *bufio.ReadWriter) {
        log.Printf("Received JSON data")
        confo := &Confo{}
        dec := json.NewDecoder(rw)
        err := dec.Decode(confo)
        if err != nil {
                fmt.Println("Error decoding JSON data", err)
                // !OK
                _, err = rw.WriteString("!OK\n")
                if err != nil {
                        fmt.Println("Cannot write to connection.\n", err)
                }
                err = rw.Flush()
                if err != nil {
                        fmt.Println("Flush failed.", err)
                }
                return
        }
        log.Printf("Confo: %v \n", confo)
        confo, err = validate(confo)
        if err != nil {
		log.Printf("Confo invalid %v \n", err)
                // !OK
                _, err = rw.WriteString("!OK\n")
                if err != nil {
                        fmt.Println("Cannot write to connection.\n", err)
                }
                err = rw.Flush()
                if err != nil {
                        fmt.Println("Flush failed.", err)
                }
                return
        }
        // OK
	_, err = rw.WriteString("OK.\n")
	if err != nil {
		log.Printf("Cannot write to connection %v \n", err)
	}
	err = rw.Flush()
	if err != nil {
		log.Printf("Flush failed %v \n", err)
	}
        select {
        case b.chc<-confo:
        default:
        }
}

// validate perform a superficial check on Confo. Devicename and Ssid must at minimum be present in Confo or error is returned. Timestamp and Coords are populated if absent and Confo returned along with nil error. 
func validate(confo *Confo) (*Confo, error) {
        if confo.Devicename == "" || confo.Ssid == "" {
                log.Printf("Recd. inadequate confo params %s %s \n", confo.Devicename, confo.Ssid)
                return nil, fmt.Errorf("Recd. inadequate confo params %s %s \n", confo.Devicename, confo.Ssid)
        }
        if confo.Coords == "" {
                log.Printf("Setting coords to defaults: %f %f \n", 77.5, 13.0)
                confo.Lng = 77.5
                confo.Lat = 13.0
        } else {
                temp := strings.Split(confo.Coords, "/")
                lng, err := strconv.ParseFloat(temp[0], 64)
                if err != nil {
                        log.Printf("ParseFloat(coords): %v \n", err)
                        confo.Lng = 77.5
                } else {
                        confo.Lng = lng
                }
                lat, err := strconv.ParseFloat(temp[1], 64)
                if err != nil {
                        log.Printf("ParseFloat(coords): %v \n", err)
                        confo.Lat = 13.0
                } else {
                        confo.Lat = lat
                }
        }
        if confo.Timestamp < 1136239445 { //  == 0 {
                log.Printf("Adding timestamp to confo %s %s \n", confo.Devicename, confo.Ssid)
                confo.Timestamp = time.Now().Unix()
                return confo, nil
        }
        return confo, nil
}

//startHttp
func (b *Broker)  startHttp() {
        mux := http.NewServeMux()
        //mux.Handle("/", http.HandlerFunc(RedirectHttp))
        mux.Handle("/confo/", http.HandlerFunc(serveHttp))
        hs := http.Server{
                ReadTimeout: /*time.Duration(httpRto)*/10 * time.Second,
                WriteTimeout: /*time.Duration(httpWto)*/10 * time.Second,
                Addr: fmt.Sprintf(":%s", b.config.HTTPPort),
                Handler: mux,
        }
        fmt.Printf("Listening for http api requests on %s \n", b.config.HTTPPort)
        err := hs.ListenAndServe()
        if err != nil {
                log.Printf("Oops: %v \n", err)
        }
}

//startHttps doesn
func (b *Broker)  startHttps() {
        mux := http.NewServeMux()
        //mux.Handle("/debug/vars", expvar.Handler())
        mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                //tlsoks.Add(1)
                //fmt.Printf("Secure visitor %s %v \n", r.RemoteAddr, *tlsoks)
                fmt.Fprintf(w, "Secure but nothing to see here \n")
        }))
        hs := http.Server{
                ReadTimeout: /*time.Duration(httpRto)*/ 10 * time.Second,
                WriteTimeout: /*time.Duration(httpWto)*/ 10 * time.Second,
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

func serveHttp(w http.ResponseWriter, r *http.Request) {
        log.Printf("Query: %v \n", r.URL.Path)
	enc := json.NewEncoder(w)
        // get the hash from the url
        toks := strings.Split(r.URL.Path, "/")
        if len(toks) < 3 {
                log.Printf("Unknown request path : %v", r.URL.Path)
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
                log.Printf("retrieve confo json encode : %v", err)
        }
        return
}
