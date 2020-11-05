## b00m-broker
Please see [b00m-broker](https://pv.b00m.in/docs/broker/)
### Build
```
./build.sh 
```
### Deploy
```
config/m0v.config is different (aligned with proxy) on prod server. Don't over-write.
```
### Run
```
./runbrokerwfunnel.sh
```
Pipes output to stdout/stderr to rotating log file.

### Test Client

go run b00m_client.go -in packet -l=false [-n=20]


