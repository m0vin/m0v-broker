package main

import (
        "crypto/tls"
        _"crypto/x509"
        "encoding/json"
        "errors"
        "flag"
        "log"
        "time"
)

var (
        input = flag.String("in", "confo", "type of input - confo|packet|packets")
        local = flag.Bool("l", false, "send confo|packet to localhost or pv.b00m.in")
        load = flag.Int("n", 1, "send n concurrent packets to localhost or pv.b00m.in")
        localUrl = "127.0.0.1:"
        remoteUrl = "pv.b00m.in:"
        p1 = "38979" // for confo
        p2 = "38981" // for packets
        p3 = "1883"
)

func main() {
        flag.Parse()
        url := ""
        if *local {
                url = localUrl
        } else {
                url = remoteUrl
        }
        // Load leaf certs
        //cert, err := tls.LoadX509KeyPair("dummy-trusted-cert.pem", "dummy-trusted-cert-key.pem")
        cert, err := tls.LoadX509KeyPair("pv.b00m.in+rsa-crt.pem", "pv.b00m.in+rsa-key.pem")
        if err != nil {
                log.Fatalf("server: loadkeys: %s", err)
        }
        config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true } //false}
        if *input == "confo" {
                url += p1
        } else {
                url += p2
        }

        if *load > 1 {
                doneChan := make(chan bool, 1)
                errChan := make(chan error, 1)
                respChan := make(chan []byte, 1)
                for i := 0; i < *load; i++ {
                        go func(n int) {
                                conn, err := tls.Dial("tcp", url, &config)
                                if err != nil {
                                        log.Fatalf("client: %d dial: %s", n, err)
                                        errChan <- err
                                        return
                                }
                                defer conn.Close()
                                log.Printf("client: %d connected to %v \n", n, conn.RemoteAddr())
                                packet := &Packet{ 987654, time.Now().Unix(), true, float64(n), 50.3} //, 32.55, float64(n)}
                                enc := json.NewEncoder(conn)
                                err = enc.Encode(packet)
                                if err != nil {
                                        log.Printf("client: %d couldn't encode to conn: %v \n", n, err)
                                        errChan <- errors.New("GET"+err.Error())
                                        return
                                } else {
                                        reply := make([]byte, 256)
                                        nbs, err := conn.Read(reply)
                                        if err != nil {
                                                errChan <- errors.New("Reply: " + err.Error())
                                                return
                                        }
                                        reply = reply[:nbs]
                                        respChan <- reply
                                        return
                                }
                                doneChan<- true
                        }(i)
                }
                for n:= 0; n < *load; {
                        select {
                                case <-doneChan:
                                        n++
                                        log.Println("Done: ", n)
                                case err = <-errChan:
                                        n++
                                        log.Println("Error: ", err)
                                case bs := <-respChan:
                                        log.Println("Done: ", string(bs))
                                        n++
                                case <-time.After(2000 * time.Millisecond):
                                        log.Println("Timeout: ", n, " timed out")
                                        n++
                        }
                        time.Sleep(100*time.Millisecond)
                }
                close(doneChan)
                close(errChan)
                close(respChan)
        } else {
                //conn, err := tls.Dial("tcp", "b00m.in:38979", &config)
                //conn, err := tls.Dial("tcp", "127.0.0.1:38979", &config)
                conn, err := tls.Dial("tcp", url, &config)
                if err != nil {
                        log.Fatalf("client: dial: %s", err)
                }
                defer conn.Close()
                log.Println("client: connected to: ", conn.RemoteAddr())

                /*state := conn.ConnectionState()
                for _, v := range state.PeerCertificates {
                        log.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
                        log.Println(v.Subject)
                }*/
                //log.Println("client: handshake: ", state.HandshakeComplete)
                //log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
                if *input == "confo" {
                        //packet := &Confo{Timestamp: time.Now().Unix(), Devicename: "Movprov", Ssid: "M0V"}
                        packet := &Confo{ Devicename:"Movprov", Ssid: "M0V", Sub: "rcs@b00m.in", Hash: 13580}
                        enc := json.NewEncoder(conn)
                        if err = enc.Encode(packet); err != nil {
                                log.Printf("client: couldn't encode to conn: %v \n", err)
                        }

                } else if *input == "packet" {
                        packet := &Packet{ 987654, time.Now().Unix(), true, 415.5, 50.3} //, 32.55, 23.444}
                        enc := json.NewEncoder(conn)
                        if err = enc.Encode(packet); err != nil {
                                log.Printf("client: couldn't encode to conn: %v \n", err)
                        }
                } else {

                }

                reply := make([]byte, 256)
                n, err := conn.Read(reply)
                log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
                log.Print("client: exiting")
        }
}

type Packet struct {
        Id int64 `json:"id!`
        Timestamp int64 `json:"timestamp,omitempty"`
        Status bool `json:"status"`
        Voltage float64 `json:"voltage"`
        Frequency float64 `json:"freq"`
        //Lat float64 `json:"lat"`
        //Lng float64 `json:"lng"`
}

type Confo struct {
        Devicename string `json:"devicename"`
        Ssid string `json:"ssid"`
        Sub string `json:"email"`
        Hash int64 `json:"hash"`
        Timestamp int64 `json:"timestamp"`
}
