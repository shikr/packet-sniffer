# Packet Sniffer

## Build

```sh
mkdir -p build
gcc -Wall -Wextra nsiff.c -o build/monitor -lraylib -lpcap -lGL -lm -lpthread -ldl -lrt -lX11
```

## Run

```sh
sudo setcap cap_net_raw=+ep ./build/monitor
./build/monitor
```

Tambien se puede ejecutar con un filtro BPF:

```sh
./build/monitor "tcp"
./build/monitor "udp"
./build/monitor "host 192.168.1.1"
```

# En caso de tener el error: 

```text
ERR: pcap_open_live() wlan0: You don't have permission to perform this capture on that device (Attempt to create packet socket failed - CAP_NET_RAW may be required)
```

Ejecutar:

```sh
sudo setcap cap_net_raw=+ep ./build/monitor
```
