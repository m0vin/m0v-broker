package main

import (
	"flag"
        "log"
        "os"
        "os/signal"
        "github.com/m0vin/m0v-broker/broker"
)

var (
        cfg = flag.String("c", "config/m0v.config", "path to config file")
)

func main() {
	log.SetFlags(log.Lshortfile)
        config, err := broker.ConfigureConfig(os.Args[1:])
        if err != nil {
                log.Printf("New config error %v \n", err)
        }

        flag.Parse() // just added this to avoid glog spamming the logs with ERROR: logging before flag.Parse:
        b, err := broker.NewBroker(config)
        if err != nil {
                log.Printf("New broker error %v \n", err)
        }
        b.Start()
        s := waitForSignal()
        log.Println("Signal received, broker terminated", s)
}

func waitForSignal() os.Signal {
        signalChan := make(chan os.Signal, 1)
        defer close(signalChan)
        signal.Notify(signalChan, os.Kill, os.Interrupt)
        s := <-signalChan
        signal.Stop(signalChan)
        return s
}

