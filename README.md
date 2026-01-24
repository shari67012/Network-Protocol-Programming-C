# Network-Protocol-Programming-C
以下皆實作於作業系統：Ubuntu 24.04 

## ARP Sniffer and Spoof Program
這是一個基於 C 語言開發的網路工具，利用 Linux 的 Raw Sockets 實現 ARP 封包的Sniffing、Query、Spoofing

### 功能簡介

Sniffer：捕捉網卡上的 ARP 封包，並解析來源與目的 IP。

Query：主動發送 ARP Request 並等待接收目標 IP 的 ARP Reply，藉此獲取 MAC 位址。

Spoof：當收到針對特定 IP 的請求時，回覆偽造的 MAC 位址。

### 環境

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

## Traceroute
這是一個基於 C 語言開發的網路工具，利用 Linux 的 Raw Sockets 與 ICMP 協定，實作類似 Traceroute 的擴展環搜尋 (Expanding Ring Search, ERS) 原語 。透過控制 IP Header 中的 TTL值，找出網路上特定Hop distance的路由器 IP 。

### 功能簡介

TTL Control：利用 setsockopt 設定 IP 封包的 TTL 值，控制封包傳輸距離 。

ICMP Request：發送 ICMP Echo Request (Type 8) 封包至指定目的地。

ICMP Response Analysis：接收並解析 ICMP Time Exceeded (Type 11) 或 Echo Reply (Type 0) 訊息，藉此識別該跳數 (Hop) 的路由器 IP 位址。

### 環境

權限要求：由於程式使用 SOCK_RAW 處理 ICMP 封包，執行時必須擁有 Root 權限 (sudo)。

### 編譯步驟
```Bash
make clean
make
```
編譯完成後，會產生執行檔。

### 使用說明
```Bash
sudo ./prog <hop-distance> <destination_ip>
```

範例：查詢特定跳數的路由器： 尋找通往 140.117.11.1 路徑上，距離來源端 3 跳 (Hop) 的路由器 IP ：
```Bash
sudo ./prog 3 140.117.11.1
```
若成功，程式將印出該路由器的 IP 位址。

若逾時 (Timeout)，程式將印出 * 符號。

若跳數設定足以到達目的地，收到 Echo Reply，程式將顯示目標已到達。

