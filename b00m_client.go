package main

import (
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "fmt"
        "log"
        "time"
)

func main() {
        // Load leaf certs
        cert, err := tls.LoadX509KeyPair("b00m-trusted-cert.pem", "b00m-trusted-cert-key.pem")
        if err != nil {
                log.Fatalf("server: loadkeys: %s", err)
        }
        config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: false}
        conn, err := tls.Dial("tcp", "b00m.in:38979", &config)
        if err != nil {
                log.Fatalf("client: dial: %s", err)
        }
        defer conn.Close()
        log.Println("client: connected to: ", conn.RemoteAddr())

        state := conn.ConnectionState()
        for _, v := range state.PeerCertificates {
                fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
                fmt.Println(v.Subject)
        }
        log.Println("client: handshake: ", state.HandshakeComplete)
        log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
        packet := &Packet{ 123, time.Now().Unix(), true, 415.5, 50.3, 32.55, 23.444}
        enc := json.NewEncoder(conn)
        if err = enc.Encode(packet); err != nil {
                log.Printf("client: couldn't encode to conn: %v \n", err)
        }

        reply := make([]byte, 256)
        n, err := conn.Read(reply)
        log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
        log.Print("client: exiting")
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


