# Network-Protocol-Programming-C
## ARP Sniffer and Spoof Program
這是一個基於 C 語言開發的網路工具，利用 Linux 的 Raw Sockets 實現 ARP 封包的Sniffing、Query、Spoofing

### 功能簡介

Sniffer：捕捉網卡上的 ARP 封包，並解析來源與目的 IP。
Query：主動發送 ARP Request 並等待接收目標 IP 的 ARP Reply，藉此獲取 MAC 位址。
Spoof：當收到針對特定 IP 的請求時，回覆偽造的 MAC 位址。

### 環境

作業系統：Linux 24.04

網卡：在 Query 與 Spoof 模式下，支援使用 -i 參數手動指定網卡，或修改 main.c 中的 #define DEVICE_NAME

### 編譯步驟

```bash
make clean
make
```
編譯完成後，會產生執行檔

### 使用說明
程式啟動格式如下：

1. Sniffer
監聽所有經過網卡的 ARP 封包 ：
```bash
sudo ./arp -l -a
```
監聽與特定 IP 相關的 ARP 封包 ：
```bash
sudo ./arp -l <filter_ip_address>
```

2. Query
查詢特定 IP 位址的實體 MAC 位址 ：
```bash
sudo ./arp -q <query_ip_address>
sudo ./arp -q <query_ip_address> -i <interface_name> //指定網卡
```

3. Spoof
當有人詢問 <target_ip_address> 時，回覆 <fake_mac_address> 給請求者 ：
```bash
sudo ./arp <fake_mac_address> <target_ip_address>
sudo ./arp <fake_mac_address> <target_ip_address> -i <interface_name> //指定網卡
```
