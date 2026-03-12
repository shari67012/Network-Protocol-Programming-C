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

ICMP Response Analysis：接收並解析 ICMP Time Exceeded (Type 11) 或 Echo Reply (Type 0) 訊息，藉此識別該跳數的路由器 IP 位址。

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


## ICMP Subnet Scanner
這是一個基於 C 語言開發的網路掃描工具，利用 Linux 的 Raw Sockets 手動建構 IP 與 ICMP 封包，並結合 libpcap 函式庫進行封包過濾與接收，實現整個子網域的主機存活掃描。

### 功能簡介
Auto-Detection：自動透過 ioctl 取得本機介面的 IP 與 Netmask，並計算出掃描的起始與結束 IP 範圍。

Raw Socket Construction：手動封裝 IP Header (包含 IP Options) 與 ICMP Header，僅針對同網段掃描，已將 IP Header 的 TTL 固定設為 1。

Packet Sniffing：使用 libpcap 設定 BPF 過濾規則，精準捕捉目標回傳的 Echo Reply。

RTT Calculation：計算發送 Request 與接收 Reply 之間的Round-Trip Time。

Timeout Handling：支援Non-blocking模式接收，可自訂每個 IP 的等待超時時間。

### 環境需求

權限：需要 Root 權限以開啟 Raw Socket。

函式庫：需要安裝 libpcap。

```Bash
sudo apt-get install libpcap-dev
```

### 編譯步驟
使用專案內附的 Makefile 進行編譯：

```Bash
make clean
make
```
編譯完成後，會產生名為 ipscanner 的執行檔。

### 使用說明
程式啟動格式如下 (必須使用 sudo)：

基本掃描指令：
指定網路介面與超時時間進行全網段掃描。

```Bash
sudo ./ipscanner -i <interface_name> -t <timeout_ms>
```
參數說明：

-i : 指定要使用的網路介面名稱。

-t : 指定等待回應的超時時間，單位為毫秒。

### 檔案結構
main.c: 主程式邏輯，負責計算網段範圍、發送封包迴圈與 RTT 計算。

fill_packet.c: 負責 IP 與 ICMP 封包表頭的填充與 Checksum 計算。

pcap.c: 負責 libpcap 的初始化、過濾規則設定與接收回應封包。

fill_packet.h / pcap.h: 相關結構定義與函式宣告。

Makefile: 編譯腳本。
