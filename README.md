# Packet Sniffer
g++ snifferUI.cpp -o build/snui -lraylib -lpcap -lGL -lm -lpthread -ldl -lrt

# En caso de tener el error: 
ERR: pcap_open_live() wlan0: You don't have permission to perform this capture on that device (Attempt to create packet socket failed - CAP_NET_RAW may be required)
Ejecutar:
sudo setcap cap_net_raw=+ep ./snui

