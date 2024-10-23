## Features:

- scan network
- cut network
- bandwidth limiting (in dev)

scan network
```bash
sudo go run ./main.go -scan -cidr 192.168.0.0/24 -i wlp49s0
```

to cut off a device
```bash
sudo go run ./main.go -i wlp49s0 -cut -ip 192.168.0.2
```
output
```
Scanning network 192.168.0.2/32...
Waiting for responses...
Discovered device: IP=192.168.0.2, MAC=7c:fd:6b:xx:xx:xx, HOSTNAME: []
Stopping packet capture after scan completion.
2024/10/23 15:42:25 Cut off device: IP: 192.168.0.2, MAC: 7c:fd:6b:xx:xx:xx, HOSTNAME: []
```