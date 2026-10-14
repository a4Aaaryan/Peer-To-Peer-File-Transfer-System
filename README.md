# P2P File Sharing System with Multi-Tracker Support

## 📌 Overview
This project implements a **peer-to-peer file sharing system** with:
- Multiple **trackers** for reliability and failover  
- A **client** that connects to trackers, executes user commands, and switches automatically to another tracker if one goes down  
- Trackers that synchronize information with each other  

The design ensures that the system continues to function even if one tracker fails.

---

## 🏗️ Components

### 1. `tracker.cpp`
- Manages user accounts, groups, and file metadata  
- Listens on two ports (service + replication)  
- Synchronizes with other trackers defined in `trackerinfo.txt`  
- Maintains the **current logged-in user** per connection  

### 2. `client.cpp`
- Connects to a tracker specified by **command-line arguments**  
- Falls back to trackers from `trackerinfo.txt` if the chosen one is unavailable  
- Sends commands entered by the user to the tracker and displays responses  
- Automatic failover when the current tracker disconnects  

---

## Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install g++ build-essential libssl-dev

# CentOS/RHEL
sudo yum install gcc-c++ openssl-devel

# macOS
brew install openssl
```

---

## ⚙️ Usage

### 1. Prepare `trackerinfo.txt`
Example:
```
T1 127.0.0.1 5000 6000
T2 127.0.0.1 5001 6001
```

### 2. Compile

```bash
g++ -std=c++11 -pthread -Wall -Wextra -O2 -o tracker Tracker/tracker.cpp -lcrypto -lssl
g++ -std=c++11 -pthread -Wall -Wextra -O2 -o client Client/client.cpp -lcrypto -lssl
```

### 3. Run Trackers

Start trackers with their ID (`T1`, `T2`, etc.): 
```bash
./tracker trackerinfo.txt T1
./tracker trackerinfo.txt T2
```

### 4. Run Client

```bash
./client <IP>:<PORT> trackerinfo.txt
```

Example:
```bash
./client 127.0.0.1:5000 trackerinfo.txt
```

The client first tries the given `<IP>:<PORT>`. If unavailable, it falls back to other trackers listed in `trackerinfo.txt`.

---

## 📁 Repository Structure
- `Tracker/tracker.cpp` — Tracker server implementation with WAL and state replication
- `Client/client.cpp` — Client peer implementation with piece selection, multi-peer downloading, and tracker failover
- `trackerinfo.txt` — Tracker configuration file
- `REPORT` — Technical implementation report