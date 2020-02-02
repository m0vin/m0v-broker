package broker

var usageStr = `
Usage: m0v-broker [options]

Broker Options:
    -p,  --port <port>                Use port for clients (default: 1883)
         --host <host>                Network host to listen on. (default "0.0.0.0")
    -c,  --config <file>              Configuration file - TLS info must be supplied in config file

Logging Options:
    -d, --debug <bool>                Enable debugging output (default false)
    -D                                Debug and trace

Common Options:
    -h, --help                        Show this message
`
