#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <set>

using namespace std;

const int CHUNK_SIZE = 512 * 1024; 

//  Structures 
struct User {
    string id;
    string password;
    bool logged_in;
    vector<string> groups;
    string client_ip;
    int client_port;
};

struct Group {
    string id;
    string owner;
    vector<string> members;
    vector<string> join_requests;
};

struct TrackerInfo {
    string id;
    string ip;
    int client_port;
    int sync_port;
};

struct FileInfo {
    string filename;
    string file_path; 
    string owner;
    long long filesize;
    vector<string> seeders; 
    vector<string> chunk_hashes;
    time_t upload_time;
};

struct PeerInfo {
    string user_id;
    string ip;
    int port;
    time_t last_seen;
};

//  Global  
unordered_map<string, vector<FileInfo>> groupFiles; // group_id -> files
map<string, User> users;
map<string, Group> groups;
map<string, PeerInfo> activePeers; // user_id -> peer info
vector<TrackerInfo> peerTrackers;

mutex walMutex;
mutex stateMutex;
mutex syncMutex;

string current_tracker_id;
bool is_sync_listener_running = false;
int sync_listener_socket = -1;

//  Helpers  
void writeWAL(const string &entry) {
    lock_guard<mutex> lock(walMutex);
    string filename = "wal_" + current_tracker_id + ".log";
    int fd = open(filename.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
    if(fd < 0) { 
        perror("open WAL"); 
        return; 
    }
    write(fd, entry.c_str(), entry.size());
    write(fd, "\n", 1);
    fsync(fd);
    close(fd);
}

vector<string> split(const string &s, char delim) {
    vector<string> elems;
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim)) {
        if(!item.empty()) elems.push_back(item);
    }
    return elems;
}

string join(const vector<string> &v, char delim=',') {
    string s;
    for(size_t i=0; i<v.size(); i++) {
        if(i>0) s += delim;
        s += v[i];
    }
    return s;
}

FileInfo* findFileInGroup(const string &groupId, const string &filename) {
    auto it = groupFiles.find(groupId);
    if(it == groupFiles.end()) return nullptr;
    
    auto &files = it->second;
    for(auto &f : files) {
        if(f.filename == filename) return &f;
    }
    return nullptr;
}

string getCurrentTime() {
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    return to_string(time);
}

// ------------------------ Tracker Synchronization ------------------------
bool connectToTracker(const TrackerInfo &tracker) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tracker.sync_port);
    inet_pton(AF_INET, tracker.ip.c_str(), &addr.sin_addr);

    if(connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }
    return true;
}

void propagateToPeers(const string &wal_entry) {
    lock_guard<mutex> lock(syncMutex);
    
    for(const auto &tracker : peerTrackers) {
        if(tracker.id == current_tracker_id) continue;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) continue;
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(tracker.sync_port);
        inet_pton(AF_INET, tracker.ip.c_str(), &addr.sin_addr);
        
        if(connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            string msg = "SYNC|" + wal_entry + "\n";
            send(sock, msg.c_str(), msg.size(), 0);
        }
        close(sock);
    }
}

void handleSyncConnection(int client_sock) {
    char buffer[8192];
    int n = read(client_sock, buffer, sizeof(buffer)-1);
    if(n <= 0) {
        close(client_sock);
        return;
    }
    buffer[n] = '\0';
    
    string message(buffer);
    if(message.find("SYNC|") == 0) {
        string wal_entry = message.substr(5);
        // Remove newline if present
        if(!wal_entry.empty() && wal_entry.back() == '\n') {
            wal_entry.pop_back();
        }
        
        // Apply the WAL entry directly
        lock_guard<mutex> lock(stateMutex);
        stringstream ss(wal_entry);
        string cmd;
        getline(ss, cmd, '|');
        
        if(cmd == "CREATE_USER") {
            string u, p; getline(ss, u, '|'); getline(ss, p, '|');
            if(users.find(u) == users.end()) users[u] = {u, p, false, {}, "", 0};
        } else if(cmd == "LOGIN") {
            string u, ip_port; getline(ss, u, '|'); getline(ss, ip_port, '|');
            if(users.find(u) != users.end()) {
                users[u].logged_in = true;
                vector<string> parts = split(ip_port, ':');
                if(parts.size() == 2) {
                    users[u].client_ip = parts[0];
                    users[u].client_port = stoi(parts[1]);
                }
            }
        } else if(cmd == "LOGOUT") {
            string u; getline(ss, u, '|');
            if(users.find(u) != users.end()) {
                users[u].logged_in = false;
                users[u].client_ip = "";
                users[u].client_port = 0;
            }
        } else if(cmd == "CREATE_GROUP") {
            string g, u; getline(ss, g, '|'); getline(ss, u, '|');
            if(groups.find(g) == groups.end()) { 
                groups[g] = {g, u, {u}, {}}; 
                users[u].groups.push_back(g); 
            }
        } else if(cmd == "JOIN_REQUEST") {
            string u, g; getline(ss, u, '|'); getline(ss, g, '|');
            if(groups.find(g) != groups.end()) {
                auto &grp = groups[g];
                if(find(grp.join_requests.begin(), grp.join_requests.end(), u) == grp.join_requests.end()) {
                    grp.join_requests.push_back(u);
                }
            }
        } else if(cmd == "ACCEPT_REQUEST") {
            string g, u; getline(ss, g, '|'); getline(ss, u, '|');
            auto &grp = groups[g];
            if(find(grp.members.begin(), grp.members.end(), u) == grp.members.end()) {
                grp.members.push_back(u);
            }
            auto it = find(grp.join_requests.begin(), grp.join_requests.end(), u);
            if(it != grp.join_requests.end()) grp.join_requests.erase(it);
            users[u].groups.push_back(g);
        } else if(cmd == "LEAVE_GROUP") {
            string u, g; getline(ss, u, '|'); getline(ss, g, '|');
            auto &grp = groups[g];
            grp.members.erase(remove(grp.members.begin(), grp.members.end(), u), grp.members.end());
            users[u].groups.erase(remove(users[u].groups.begin(), users[u].groups.end(), g), users[u].groups.end());
        } else if(cmd == "UPLOAD_FILE") {
            // Format: UPLOAD_FILE|gid|uid|fname|fpath|realFileSize|hash1,hash2,...
            string gid, uid, fname, fpath, sizeStr, hashes; 
            getline(ss, gid, '|'); getline(ss, uid, '|'); 
            getline(ss, fname, '|'); getline(ss, fpath, '|');
            getline(ss, sizeStr, '|'); getline(ss, hashes, '|');
            
            long long realFileSize = 0;
            try { realFileSize = stoll(sizeStr); } catch(...) {}
            if(realFileSize <= 0) realFileSize = (long long)split(hashes, ',').size() * CHUNK_SIZE;
            
            // Remove existing file if present
            auto &files = groupFiles[gid];
            files.erase(remove_if(files.begin(), files.end(),
                [&](FileInfo &f){ return f.filename == fname && f.owner == uid; }), files.end());
                
            groupFiles[gid].push_back({fname, fpath, uid, realFileSize,
                                      {uid}, split(hashes, ','), time(nullptr)});
        } else if(cmd == "STOP_SHARE") {
            string gid, uid, fname; 
            getline(ss, gid, '|'); getline(ss, uid, '|'); getline(ss, fname, '|');
            auto &files = groupFiles[gid];
            files.erase(remove_if(files.begin(), files.end(),
                [&](FileInfo &f){ return f.filename == fname && f.owner == uid; }), files.end());
        }
        
        // Also write to local WAL
        writeWAL(wal_entry);
    }
    
    close(client_sock);
}

void syncListener(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0) {
        perror("sync socket");
        return;
    }
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if(bind(server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sync bind");
        close(server_sock);
        return;
    }
    
    if(listen(server_sock, 5) < 0) {
        perror("sync listen");
        close(server_sock);
        return;
    }
    
    sync_listener_socket = server_sock;
    is_sync_listener_running = true;
    
    cout << "Sync listener running on port " << port << endl;
    
    while(is_sync_listener_running) {
        int client_sock = accept(server_sock, nullptr, nullptr);
        if(client_sock >= 0) {
            thread(handleSyncConnection, client_sock).detach();
        }
    }
    
    close(server_sock);
}

// ------------------------ WAL Apply ------------------------
void applyWALLine(const string &line) {
    lock_guard<mutex> lock(stateMutex);
    stringstream ss(line);
    string cmd;
    getline(ss, cmd, '|');

    if(cmd == "CREATE_USER") {
        string u, p; getline(ss, u, '|'); getline(ss, p, '|');
        if(users.find(u) == users.end()) users[u] = {u, p, false, {}, "", 0};
    } else if(cmd == "LOGIN") {
        string u, ip_port; getline(ss, u, '|'); getline(ss, ip_port, '|');
        if(users.find(u) != users.end()) {
            users[u].logged_in = true;
            vector<string> parts = split(ip_port, ':');
            if(parts.size() == 2) {
                users[u].client_ip = parts[0];
                users[u].client_port = stoi(parts[1]);
            }
        }
    } else if(cmd == "LOGOUT") {
        string u; getline(ss, u, '|');
        if(users.find(u) != users.end()) {
            users[u].logged_in = false;
            users[u].client_ip = "";
            users[u].client_port = 0;
        }
    } else if(cmd == "CREATE_GROUP") {
        string g, u; getline(ss, g, '|'); getline(ss, u, '|');
        if(groups.find(g) == groups.end()) { 
            groups[g] = {g, u, {u}, {}}; 
            users[u].groups.push_back(g); 
        }
    } else if(cmd == "JOIN_REQUEST") {
        string u, g; getline(ss, u, '|'); getline(ss, g, '|');
        if(groups.find(g) != groups.end()) {
            auto &grp = groups[g];
            if(find(grp.join_requests.begin(), grp.join_requests.end(), u) == grp.join_requests.end()) {
                grp.join_requests.push_back(u);
            }
        }
    } else if(cmd == "ACCEPT_REQUEST") {
        string g, u; getline(ss, g, '|'); getline(ss, u, '|');
        auto &grp = groups[g];
        if(find(grp.members.begin(), grp.members.end(), u) == grp.members.end()) {
            grp.members.push_back(u);
        }
        auto it = find(grp.join_requests.begin(), grp.join_requests.end(), u);
        if(it != grp.join_requests.end()) grp.join_requests.erase(it);
        users[u].groups.push_back(g);
    } else if(cmd == "LEAVE_GROUP") {
        string u, g; getline(ss, u, '|'); getline(ss, g, '|');
        auto &grp = groups[g];
        grp.members.erase(remove(grp.members.begin(), grp.members.end(), u), grp.members.end());
        users[u].groups.erase(remove(users[u].groups.begin(), users[u].groups.end(), g), users[u].groups.end());
    } else if(cmd == "UPLOAD_FILE") {
        // Format: UPLOAD_FILE|gid|uid|fname|fpath|realFileSize|hash1,hash2,...
        string gid, uid, fname, fpath, sizeStr, hashes; 
        getline(ss, gid, '|'); getline(ss, uid, '|'); 
        getline(ss, fname, '|'); getline(ss, fpath, '|');
        getline(ss, sizeStr, '|'); getline(ss, hashes, '|');
        
        long long realFileSize = 0;
        try { realFileSize = stoll(sizeStr); } catch(...) {}
        if(realFileSize <= 0) realFileSize = (long long)split(hashes, ',').size() * CHUNK_SIZE;
        
        // Remove existing file if present
        auto &files = groupFiles[gid];
        files.erase(remove_if(files.begin(), files.end(),
            [&](FileInfo &f){ return f.filename == fname && f.owner == uid; }), files.end());
            
        groupFiles[gid].push_back({fname, fpath, uid, realFileSize,
                                  {uid}, split(hashes, ','), time(nullptr)});
    } else if(cmd == "STOP_SHARE") {
        string gid, uid, fname; 
        getline(ss, gid, '|'); getline(ss, uid, '|'); getline(ss, fname, '|');
        auto &files = groupFiles[gid];
        files.erase(remove_if(files.begin(), files.end(),
            [&](FileInfo &f){ return f.filename == fname && f.owner == uid; }), files.end());
    }
}

void replayWAL(const string &tracker_id) {
    string filename = "wal_" + tracker_id + ".log";
    int fd = open(filename.c_str(), O_RDONLY);
    if(fd < 0) return;

    char buf[8192]; 
    ssize_t n; 
    string leftover;
    
    while((n = read(fd, buf, sizeof(buf))) > 0) {
        string chunk(buf, n); 
        chunk = leftover + chunk;
        size_t pos = 0, lastPos = 0;
        
        while((pos = chunk.find('\n', lastPos)) != string::npos) {
            string line = chunk.substr(lastPos, pos - lastPos);
            if(!line.empty()) {
                applyWALLine(line);
            }
            lastPos = pos + 1;
        }
        leftover = chunk.substr(lastPos);
    }
    
    // Apply any trailing partial line that had no newline at end of file
    if(!leftover.empty() && leftover.find_first_not_of(" \t\n\r") != string::npos) {
        applyWALLine(leftover);
    }
    
    close(fd);
}

// ------------------------ Specialized Command Handlers ------------------------
string handleListRequests(const string &groupId, const string &currentUser) {
    if(groups.find(groupId) == groups.end()) return "Error: Group not found\n";
    if(groups[groupId].owner != currentUser) return "Error: Only owner can view requests\n";
    
    auto &requests = groups[groupId].join_requests;
    if(requests.empty()) return "No pending requests\n";
    
    string out = "Pending join requests:\n";
    for(auto &req : requests) out += " - " + req + "\n";
    return out;
}

string handleLeaveGroup(const string &groupId, const string &currentUser) {
    if(groups.find(groupId) == groups.end()) return "Error: Group not found\n";
    
    auto &grp = groups[groupId];
    if(grp.owner == currentUser) return "Error: Owner cannot leave group\n";
    
    auto it = find(grp.members.begin(), grp.members.end(), currentUser);
    if(it == grp.members.end()) return "Error: Not a member of this group\n";
    
    grp.members.erase(it);
    users[currentUser].groups.erase(
        remove(users[currentUser].groups.begin(), users[currentUser].groups.end(), groupId), 
        users[currentUser].groups.end());
    
    writeWAL("LEAVE_GROUP|" + currentUser + "|" + groupId);
    propagateToPeers("LEAVE_GROUP|" + currentUser + "|" + groupId);
    
    return "Left group successfully\n";
}

string handleFileInfo(const string &groupId, const string &filename) {
    FileInfo* file = findFileInGroup(groupId, filename);
    if(!file) return "Error: File not found\n";
    
    stringstream ss;
    ss << file->filesize << " " << file->chunk_hashes.size();
    for(auto &hash : file->chunk_hashes) {
        ss << " " << hash;
    }
    ss << "\n";
    
    // Add peer information
    ss << "SEEDERS:";
    for(auto &seeder : file->seeders) {
        if(users.find(seeder) != users.end() && users[seeder].logged_in) {
            ss << " " << users[seeder].client_ip << ":" << users[seeder].client_port;
        }
    }
    ss << "\n";
    
    return ss.str();
}

// ------------------------ Command Execution ------------------------
string executeCommand(const string &cmdLine, const string &tracker_id, string &currentUser, const string &client_ip = "", int client_port = 0) {
    // Build the WAL entry and response while holding stateMutex,
    // then propagate OUTSIDE the lock so a slow peer tracker cannot
    // freeze all client connections by blocking inside connect().
    string wal_entry;
    string response;

    {
        lock_guard<mutex> lock(stateMutex);
        stringstream ss(cmdLine);
        string action; 
        ss >> action;

        if(action == "create_user") {
            string uid, pwd; 
            ss >> uid >> pwd;
            if(uid.empty() || pwd.empty()) { response = "Error: usage create_user <user> <password>\n"; goto done; }
            if(users.find(uid) != users.end()) { response = "Error: User already exists\n"; goto done; }
            
            users[uid] = {uid, pwd, false, {}, "", 0};
            wal_entry = "CREATE_USER|" + uid + "|" + pwd;
            response = "User created\n";
            
        } else if(action == "login") {
            string uid, pwd;
            ss >> uid >> pwd;
            if(uid.empty() || pwd.empty()) { response = "Error: usage login <user> <password>\n"; goto done; }
            if(users.find(uid) == users.end()) { response = "Error: No such user\n"; goto done; }
            if(users[uid].password != pwd) { response = "Error: Invalid password\n"; goto done; }

            // The client sends its SEEDING listen port as the third argument:
            //   login <uid> <pwd> <seed_port>
            // If omitted we fall back to the TCP source port (old behaviour).
            int seed_port = client_port;
            string seed_port_str;
            if(ss >> seed_port_str) {
                try { seed_port = stoi(seed_port_str); } catch(...) {}
            }

            users[uid].logged_in = true; 
            users[uid].client_ip  = client_ip;
            users[uid].client_port = seed_port;
            currentUser = uid;

            string ip_port = client_ip + ":" + to_string(seed_port);
            wal_entry = "LOGIN|" + uid + "|" + ip_port;
            response = "Login successful\n";
            
        } else if(action == "logout") {
            string uid = currentUser; 
            currentUser.clear();
            if(uid.empty()) { response = "Error: Not logged in\n"; goto done; }
            
            users[uid].logged_in = false;
            users[uid].client_ip = "";
            users[uid].client_port = 0;
            
            wal_entry = "LOGOUT|" + uid;
            response = "Logout successful\n";
            
        } else if(action == "create_group") {
            string gid; 
            ss >> gid;
            if(gid.empty()) { response = "Error: usage create_group <group_id>\n"; goto done; }
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(groups.find(gid) != groups.end()) { response = "Error: Group already exists\n"; goto done; }
            
            groups[gid] = {gid, currentUser, {currentUser}, {}};
            users[currentUser].groups.push_back(gid);
            
            wal_entry = "CREATE_GROUP|" + gid + "|" + currentUser;
            response = "Group created\n";
            
        } else if(action == "join_group") {
            string gid; 
            ss >> gid;
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(gid.empty()) { response = "Error: usage join_group <group_id>\n"; goto done; }
            if(groups.find(gid) == groups.end()) { response = "Error: Group not found\n"; goto done; }
            
            auto &grp = groups[gid];
            if(find(grp.members.begin(), grp.members.end(), currentUser) != grp.members.end()) 
                { response = "Error: Already a member\n"; goto done; }
                
            auto &reqs = grp.join_requests;
            if(find(reqs.begin(), reqs.end(), currentUser) != reqs.end()) 
                { response = "Error: Already requested\n"; goto done; }
                
            reqs.push_back(currentUser);
            wal_entry = "JOIN_REQUEST|" + currentUser + "|" + gid;
            response = "Join request sent\n";
            
        } else if(action == "accept_request") {
            string gid, uid; 
            ss >> gid >> uid;
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(gid.empty() || uid.empty()) { response = "Error: usage accept_request <group_id> <user>\n"; goto done; }
            if(groups.find(gid) == groups.end()) { response = "Error: Group not found\n"; goto done; }
            if(groups[gid].owner != currentUser) { response = "Error: Only owner can accept\n"; goto done; }
            
            auto &grp = groups[gid]; 
            auto it = find(grp.join_requests.begin(), grp.join_requests.end(), uid);
            if(it == grp.join_requests.end()) { response = "Error: No such request\n"; goto done; }
            
            if(find(grp.members.begin(), grp.members.end(), uid) == grp.members.end()) 
                grp.members.push_back(uid);
            grp.join_requests.erase(it); 
            users[uid].groups.push_back(gid);
            
            wal_entry = "ACCEPT_REQUEST|" + gid + "|" + uid;
            response = "Request accepted\n";
            
        } else if(action == "list_requests") {
            string gid; 
            ss >> gid;
            if(gid.empty()) { response = "Error: usage list_requests <group_id>\n"; goto done; }
            response = handleListRequests(gid, currentUser);
            goto done; // read-only, no WAL
            
        } else if(action == "leave_group") {
            string gid; 
            ss >> gid;
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(gid.empty()) { response = "Error: usage leave_group <group_id>\n"; goto done; }
            response = handleLeaveGroup(gid, currentUser);
            // handleLeaveGroup writes its own WAL+propagate, so skip here
            goto done;
            
        } else if(action == "list_groups") {
            string out = "Groups:\n";
            for(auto &g : groups) {
                out += " - " + g.first + " (Owner: " + g.second.owner + ", Members: " + to_string(g.second.members.size()) + ")\n";
            }
            response = out.empty() ? "No groups\n" : out;
            goto done; // read-only
            
        } else if(action == "upload_file") {
            string gid, filePath;
            ss >> gid >> filePath;
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(gid.empty() || filePath.empty()) { response = "Error: usage upload_file <group_id> <file_path>\n"; goto done; }
            if(groups.find(gid) == groups.end()) { response = "Error: Group not found\n"; goto done; }
            
            auto &grp = groups[gid];
            if(find(grp.members.begin(), grp.members.end(), currentUser) == grp.members.end())
                { response = "Error: Not a group member\n"; goto done; }

            // New protocol: upload_file <gid> <path> <realFileSize> <hash1,hash2,...>
            long long realFileSize = 0;
            string hashListStr;
            ss >> realFileSize;
            getline(ss, hashListStr);
            hashListStr.erase(0, hashListStr.find_first_not_of(" \t"));
            
            if(hashListStr.empty()) { response = "Error: No chunk hashes provided\n"; goto done; }
            
            vector<string> chunk_hashes = split(hashListStr, ',');
            string filename = filePath.substr(filePath.find_last_of("/\\") + 1);
            
            // Remove existing entry for this user+file (re-upload / new seeder)
            auto &files = groupFiles[gid];
            files.erase(remove_if(files.begin(), files.end(),
                [&](FileInfo &f){ return f.filename == filename && f.owner == currentUser; }), files.end());
            
            // Use the real file size sent by the client instead of padding to chunk boundary
            if(realFileSize <= 0) realFileSize = (long long)chunk_hashes.size() * CHUNK_SIZE;
            groupFiles[gid].push_back({filename, filePath, currentUser, realFileSize, {currentUser}, chunk_hashes, time(nullptr)});
            
            wal_entry = "UPLOAD_FILE|" + gid + "|" + currentUser + "|" + filename + "|" + filePath
                        + "|" + to_string(realFileSize) + "|" + join(chunk_hashes);
            response = "File uploaded successfully\n";
            
        } else if(action == "list_files") {
            string gid; 
            ss >> gid;
            if(gid.empty()) { response = "Error: usage list_files <group_id>\n"; goto done; }
            if(groups.find(gid) == groups.end()) { response = "Error: Group not found\n"; goto done; }
            
            string out = "Files in group " + gid + ":\n";
            auto it = groupFiles.find(gid);
            if(it != groupFiles.end()) {
                for(auto &f : it->second) {
                    out += " - " + f.filename + " (Owner: " + f.owner + ", Size: " + to_string(f.filesize) + " bytes, Seeders: " + to_string(f.seeders.size()) + ")\n";
                }
            }
            response = out.empty() ? "No files\n" : out;
            goto done; // read-only
            
        } else if(action == "file_info") {
            string gid, fname; 
            ss >> gid >> fname;
            if(gid.empty() || fname.empty()) { response = "Error: usage file_info <group_id> <file_name>\n"; goto done; }
            response = handleFileInfo(gid, fname);
            goto done; // read-only
            
        } else if(action == "stop_share") {
            string gid, fname; 
            ss >> gid >> fname;
            if(currentUser.empty()) { response = "Error: must be logged in\n"; goto done; }
            if(gid.empty() || fname.empty()) { response = "Error: usage stop_share <group_id> <file_name>\n"; goto done; }
            
            auto &files = groupFiles[gid];
            auto it = find_if(files.begin(), files.end(),
                [&](FileInfo &f){ return f.filename == fname && f.owner == currentUser; });
            if(it == files.end()) { response = "Error: file not found or not owner\n"; goto done; }
            
            files.erase(it); 
            wal_entry = "STOP_SHARE|" + gid + "|" + currentUser + "|" + fname;
            response = "Stopped sharing file\n";
        } else {
            response = "Error: Unknown command\n";
            goto done;
        }

        // Write WAL under the state lock (walMutex is nested inside stateMutex here)
        if(!wal_entry.empty()) writeWAL(wal_entry);
    } // stateMutex released

    done:
    // Propagate to peer trackers OUTSIDE stateMutex so a slow/down peer cannot
    // stall the current tracker's client handler threads.
    if(!wal_entry.empty()) propagateToPeers(wal_entry);
    return response;
}

// ------------------------ Client Connection Handler ------------------------
void handleClient(int clientSock, const sockaddr_in &clientAddr, const string &tracker_id) {
    char buffer[8192];
    string currentUser;
    
    string client_ip = inet_ntoa(clientAddr.sin_addr);
    int client_port = ntohs(clientAddr.sin_port);
    
    cout << "[Tracker " << tracker_id << "] Client connected: " << client_ip << ":" << client_port << endl;
    
    while(true) {
        int n = read(clientSock, buffer, sizeof(buffer)-1);
        if(n <= 0) break;
        buffer[n] = '\0';
        
        string cmd(buffer); 
        cmd.erase(cmd.find_last_not_of("\n\r")+1);

        cout << "[Tracker " << tracker_id << "] Received from " << client_ip << ":" << client_port << ": " << cmd << endl;
        
        if(cmd == "quit" || cmd == "exit") break;

        string response = executeCommand(cmd, tracker_id, currentUser, client_ip, client_port);
        write(clientSock, response.c_str(), response.size());
    }

    // Logout user if they were logged in when the TCP connection drops
    if(!currentUser.empty()) {
        string wal_logout;
        {
            lock_guard<mutex> lock(stateMutex);
            if(users.find(currentUser) != users.end()) {
                users[currentUser].logged_in = false;
                users[currentUser].client_ip = "";
                users[currentUser].client_port = 0;
                wal_logout = "LOGOUT|" + currentUser;
                writeWAL(wal_logout);
            }
        }
        if(!wal_logout.empty()) propagateToPeers(wal_logout);
    }
    
    cout << "[Tracker " << tracker_id << "] Client disconnected: " << client_ip << ":" << client_port << endl;
    close(clientSock);
}

void clientListener(int port, const string &tracker_id) {
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSock < 0) { 
        perror("client socket"); 
        return; 
    }

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(serverSock, (sockaddr*)&addr, sizeof(addr)) < 0) { 
        perror("client bind"); 
        close(serverSock);
        return; 
    }
    
    if(listen(serverSock, 10) < 0) { 
        perror("client listen"); 
        close(serverSock);
        return; 
    }

    cout << "Client listener running on port " << port << "\n";
    
    while(true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clientLen);
        if(clientSock >= 0) {
            thread(handleClient, clientSock, clientAddr, tracker_id).detach();
        } else {
            perror("accept");
        }
    }
    
    close(serverSock);
}

// ------------------------ Tracker Info ------------------------
vector<TrackerInfo> readTrackerInfo(const string &filename) {
    vector<TrackerInfo> trackers;
    int fd = open(filename.c_str(), O_RDONLY);
    if(fd < 0) { 
        perror("open tracker info"); 
        exit(1); 
    }

    char buf[8192]; 
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    if(n < 0) { 
        perror("read"); 
        close(fd);
        exit(1); 
    }
    buf[n] = '\0'; 
    close(fd);

    char *line = strtok(buf, "\n");
    while(line) {
        stringstream ss(line);
        string id, ip; 
        int client_port, sync_port;
        if(ss >> id >> ip >> client_port >> sync_port) {
            trackers.push_back({id, ip, client_port, sync_port});
        }
        line = strtok(nullptr, "\n");
    }
    return trackers;
}

// ------------------------ Cleanup ------------------------
void cleanup() {
    is_sync_listener_running = false;
    if(sync_listener_socket >= 0) {
        close(sync_listener_socket);
    }
}

// ------------------------ Main ------------------------
int main(int argc, char *argv[]) {
    if(argc != 3) { 
        cerr << "Usage: ./tracker tracker_info.txt <tracker_number>\n"; 
        return 1; 
    }

    string tracker_info_file = argv[1];
    string tracker_number = argv[2];
    
    vector<TrackerInfo> trackers = readTrackerInfo(tracker_info_file);
    if(trackers.size() < 2) {
        cerr << "Error: Need at least 2 trackers in info file\n";
        return 1;
    }

    // Determine which tracker we are
    TrackerInfo *self = nullptr;
    for(auto &t : trackers) {
        if(t.id == tracker_number) {
            self = &t;
            break;
        }
    }
    
    if(!self) {
        cerr << "Error: Tracker ID " << tracker_number << " not found in tracker info file\n";
        return 1;
    }

    current_tracker_id = tracker_number;
    peerTrackers = trackers;

    cout << "Starting Tracker " << current_tracker_id << endl;
    cout << "Client Port: " << self->client_port << endl;
    cout << "Sync Port: " << self->sync_port << endl;
    cout << "IP: " << self->ip << endl;

    // Replay WAL for recovery
    replayWAL(current_tracker_id);

    // Start sync listener for tracker synchronization
    thread(syncListener, self->sync_port).detach();

    // Start client listener
    thread(clientListener, self->client_port, current_tracker_id).detach();

    // Handle console commands for tracker management
    string cmd;
    while(true) {
        cout << "tracker> ";
        if(!getline(cin, cmd)) break;
        
        if(cmd == "quit" || cmd == "exit") {
            cout << "Shutting down tracker...\n";
            break;
        } else if(cmd == "status") {
            lock_guard<mutex> lock(stateMutex);
            cout << "Tracker Status:\n";
            cout << " - Users: " << users.size() << endl;
            cout << " - Groups: " << groups.size() << endl;
            cout << " - Active Peers: " << activePeers.size() << endl;
        } else if(cmd == "help") {
            cout << "Available commands:\n";
            cout << "  status - Show tracker status\n";
            cout << "  quit - Shutdown tracker\n";
        } else {
            cout << "Unknown tracker command. Type 'help' for available commands.\n";
        }
    }

    cleanup();
    return 0;
}