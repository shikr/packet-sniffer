# Packet Sniffer

## Build

```sh
make
```

## Run

```sh
sudo setcap cap_net_raw=+ep ./build/packet-sniffer
./build/packet-sniffer
```

## Troubleshooting

If you encounter the following error when trying to run the packet sniffer:

```text
Could not open device wlan0: wlan0: You don't have permission to perform this capture on that device
```

Run:

```sh
sudo setcap cap_net_raw=+ep ./build/monitor
```
