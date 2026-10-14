#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <map>
#include <set>
#include <chrono>
#include <atomic>
#include <memory>

using namespace std;

// ------------------------ Constants ------------------------
const size_t CHUNK_SIZE = 512 * 1024; // 512KB as required

// ------------------------ Structures ------------------------
struct Tracker {
    string ip;
    int port;
    string id;
};

struct DownloadTask {
    string groupId;
    string filename;
    string destPath;
    long long downloadedBytes;
    long long totalSize;
    bool completed;
    vector<bool> downloadedChunks;
    vector<string> chunkHashes;
    vector<string> seeders; // Available peers for this file
    mutex taskMutex;
    
    DownloadTask() : downloadedBytes(0), totalSize(0), completed(false) {}
};

struct PeerConnection {
    string ip;
    int port;
    int socket;
};

// ------------------------ Global State ------------------------
vector<Tracker> trackers;
int activeTrackerIndex = -1;
int tracker_sock = -1;
string current_user;
string client_ip;
int client_port = 0;

vector<shared_ptr<DownloadTask>> downloads; // Use shared_ptr to avoid copy issues
mutex downloadsMutex;

atomic<bool> is_seeding(false);
int peer_server_socket = -1;

// Maps filename -> absolute disk path so the seeding service can locate files
mutex localFilesMutex;
unordered_map<string, string> localFilePaths;

// ------------------------ Utility Functions ------------------------
string sha1sum(const unsigned char* data, size_t len) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, len, hash);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

vector<string> calculateFileChunkHashes(const string &filePath) {
    vector<string> hashes;
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open file for hashing");
        return hashes;
    }

    unsigned char buffer[CHUNK_SIZE];
    ssize_t bytesRead;
    
    while ((bytesRead = read(fd, buffer, CHUNK_SIZE)) > 0) {
        hashes.push_back(sha1sum(buffer, bytesRead));
    }
    
    if (bytesRead < 0) {
        perror("read file for hashing");
    }
    
    close(fd);
    return hashes;
}

vector<string> split(const string &s, char delim) {
    vector<string> elems;
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        if (!item.empty()) elems.push_back(item);
    }
    return elems;
}

bool fileExists(const string &path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

long long getFileSize(const string &path) {
    struct stat stat_buf;
    int rc = stat(path.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

// ------------------------ Tracker Communication ------------------------
int connectToTracker(const Tracker &tracker) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tracker.port);
    
    if (inet_pton(AF_INET, tracker.ip.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    // Set timeout for connection
    timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

bool establishConnection() {
    for (size_t i = 0; i < trackers.size(); i++) {
        int sock = connectToTracker(trackers[i]);
        if (sock >= 0) {
            if (tracker_sock >= 0) {
                close(tracker_sock);
            }
            tracker_sock = sock;
            activeTrackerIndex = i;
            cout << "Connected to tracker " << trackers[i].ip << ":" << trackers[i].port << endl;
            return true;
        }
    }
    return false;
}

bool sendToTracker(const string &message) {
    if (tracker_sock < 0) {
        if (!establishConnection()) {
            return false;
        }
    }

    string msg = message;
    if (msg.back() != '\n') msg.push_back('\n');

    ssize_t sent = send(tracker_sock, msg.c_str(), msg.size(), 0);
    if (sent <= 0) {
        cerr << "Failed to send to tracker, reconnecting..." << endl;
        close(tracker_sock);
        tracker_sock = -1;
        return false;
    }

    return true;
}

string receiveFromTracker() {
    if (tracker_sock < 0) return "";

    char buffer[8192];
    ssize_t received = recv(tracker_sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        cerr << "Tracker disconnected" << endl;
        close(tracker_sock);
        tracker_sock = -1;
        return "";
    }
    
    buffer[received] = '\0';
    return string(buffer);
}

string sendCommand(const string &cmd) {
    if (!sendToTracker(cmd)) {
        return "Error: Cannot connect to any tracker\n";
    }
    
    string response = receiveFromTracker();
    if (response.empty()) {
        return "Error: No response from tracker\n";
    }
    
    return response;
}

// ------------------------ Peer-to-Peer Communication ------------------------
int connectToPeer(const string &ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    // Set timeout
    timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

bool downloadChunkFromPeer(const string &peer_ip, int peer_port, 
                          const string &groupId, const string &filename, 
                          int chunkIndex, vector<unsigned char> &chunkData) {
    int peer_sock = connectToPeer(peer_ip, peer_port);
    if (peer_sock < 0) {
        cerr << "Failed to connect to peer " << peer_ip << ":" << peer_port << endl;
        return false;
    }

    // Request chunk from peer
    string request = "GET_CHUNK " + groupId + " " + filename + " " + to_string(chunkIndex) + "\n";
    cout << "Requesting chunk " << chunkIndex << " from " << peer_ip << ":" << peer_port << endl;
    
    if (send(peer_sock, request.c_str(), request.size(), MSG_NOSIGNAL) <= 0) {
        cerr << "Failed to send request to peer" << endl;
        close(peer_sock);
        return false;
    }

    // Receive chunk data - may be smaller than CHUNK_SIZE for the last chunk.
    // Read until the peer closes the connection or we fill the buffer.
    chunkData.clear();
    chunkData.resize(CHUNK_SIZE);
    ssize_t totalReceived = 0;
    
    while (totalReceived < (ssize_t)CHUNK_SIZE) {
        ssize_t received = recv(peer_sock, chunkData.data() + totalReceived, 
                               CHUNK_SIZE - totalReceived, 0);
        if (received < 0) {
            // EAGAIN/EWOULDBLOCK means timeout; treat partial data as last-chunk EOF
            if (totalReceived > 0) break;
            cerr << "Failed to receive data from peer" << endl;
            close(peer_sock);
            return false;
        }
        if (received == 0) break; // peer closed connection = end of chunk data
        totalReceived += received;
    }

    close(peer_sock);
    if (totalReceived == 0) {
        cerr << "Received 0 bytes from peer" << endl;
        return false;
    }
    chunkData.resize(totalReceived);
    cout << "Successfully downloaded chunk " << chunkIndex << " (" << totalReceived << " bytes)" << endl;
    return true;
}

void handlePeerRequest(int client_sock, const sockaddr_in &client_addr) {
    char buffer[1024];
    ssize_t n = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        close(client_sock);
        return;
    }
    buffer[n] = '\0';

    string request(buffer);
    // Strip trailing newline
    if (!request.empty() && request.back() == '\n') request.pop_back();
    cout << "Received peer request: " << request << endl;
    
    if (request.find("GET_CHUNK ") == 0) {
        stringstream ss(request);
        string cmd, groupId, filename;
        int chunkIndex;
        ss >> cmd >> groupId >> filename >> chunkIndex;

        // Sanitize filename: reject path traversal attempts
        if (filename.find("..") != string::npos || filename.find('/') != string::npos) {
            cerr << "Rejected path traversal attempt: " << filename << endl;
            close(client_sock);
            return;
        }

        // Look up the actual disk path from our local registry
        string localPath;
        {
            lock_guard<mutex> lk(localFilesMutex);
            auto it = localFilePaths.find(filename);
            if (it != localFilePaths.end()) localPath = it->second;
        }
        // Fallback: try current directory
        if (localPath.empty() && fileExists(filename)) localPath = filename;
        
        if (localPath.empty()) {
            cout << "File not found: " << filename << endl;
            close(client_sock);
            return;
        }

        int fd = open(localPath.c_str(), O_RDONLY);
        if (fd < 0) {
            cout << "Failed to open file: " << localPath << endl;
            close(client_sock);
            return;
        }

        struct stat fileStat;
        fstat(fd, &fileStat);
        long long fileSize = fileStat.st_size;
        
        off_t offset = chunkIndex * CHUNK_SIZE;
        if (lseek(fd, offset, SEEK_SET) < 0) {
            cout << "Seek failed for chunk " << chunkIndex << endl;
            close(fd);
            close(client_sock);
            return;
        }

        unsigned char chunkBuffer[CHUNK_SIZE];
        ssize_t bytesRead = read(fd, chunkBuffer, CHUNK_SIZE);
        
        if (bytesRead > 0) {
            ssize_t sent = send(client_sock, chunkBuffer, bytesRead, 0);
            cout << "Sent " << sent << " bytes for chunk " << chunkIndex << endl;
        } else {
            cout << "Read failed for chunk " << chunkIndex << endl;
        }

        close(fd);
    }

    close(client_sock);
}

void startSeedingService(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("peer server socket");
        return;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("peer server bind");
        close(server_sock);
        return;
    }

    if (listen(server_sock, 5) < 0) {
        perror("peer server listen");
        close(server_sock);
        return;
    }

    peer_server_socket = server_sock;
    is_seeding = true;

    cout << "Peer server running on port " << port << endl;

    while (is_seeding) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (sockaddr*)&client_addr, &client_len);
        if (client_sock >= 0) {
            thread(handlePeerRequest, client_sock, client_addr).detach();
        }
    }

    close(server_sock);
}

//  File Operations 
bool uploadFile(const string &groupId, const string &filePath) {
    if (!fileExists(filePath)) {
        cout << "Error: File not found" << endl;
        return false;
    }

    // Get real file size before chunking
    long long realFileSize = getFileSize(filePath);
    if (realFileSize < 0) {
        cout << "Error: Cannot stat file" << endl;
        return false;
    }

    // Calculate chunk hashes
    vector<string> chunkHashes = calculateFileChunkHashes(filePath);
    if (chunkHashes.empty()) {
        cout << "Error: Failed to calculate file hashes" << endl;
        return false;
    }

    // Build comma-separated hash list (tracker parses with split(hashListStr, ','))
    string hashList;
    for (size_t i = 0; i < chunkHashes.size(); i++) {
        if (i > 0) hashList += ",";
        hashList += chunkHashes[i];
    }

    // Command format: upload_file <group> <path> <realFileSize> <hash1,hash2,...>
    stringstream cmd;
    cmd << "upload_file " << groupId << " " << filePath << " " << realFileSize << " " << hashList;

    string response = sendCommand(cmd.str());
    cout << response;

    if (response.find("Error") == string::npos) {
        // Register this file path locally so we can serve chunks
        string filename = filePath.substr(filePath.find_last_of("/\\") + 1);
        lock_guard<mutex> lk(localFilesMutex);
        localFilePaths[filename] = filePath;
        return true;
    }
    return false;
}

void downloadFile(const string &groupId, const string &filename, const string &destPath) {
    // First get file info from tracker
    string infoCmd = "file_info " + groupId + " " + filename;
    string response = sendCommand(infoCmd);
    
    if (response.find("Error") != string::npos) {
        cout << response;
        return;
    }

    // Parse file info
    // Format: <fileSize> <numChunks> <hash0> <hash1> ... \n SEEDERS: <ip:port> ...\n
    stringstream ss(response);
    long long fileSize;
    int numChunks;
    ss >> fileSize >> numChunks;
    
    vector<string> chunkHashes(numChunks);
    for (int i = 0; i < numChunks; i++) {
        ss >> chunkHashes[i];
    }

    // Parse seeders
    string line;
    getline(ss, line); // consume remainder of first line
    getline(ss, line); // SEEDERS: line
    
    vector<string> seeders;
    if (line.find("SEEDERS:") == 0) {
        string seederList = line.substr(8);
        // seederList is space-separated "ip:port" entries
        stringstream seedSS(seederList);
        string entry;
        while (seedSS >> entry) seeders.push_back(entry);
    }

    if (seeders.empty()) {
        cout << "Error: No seeders available for this file" << endl;
        return;
    }

    // Create download task using shared_ptr
    auto task = make_shared<DownloadTask>();
    task->groupId = groupId;
    task->filename = filename;
    task->destPath = destPath;
    task->totalSize = fileSize;
    task->downloadedBytes = 0;
    task->completed = false;
    task->downloadedChunks.resize(numChunks, false);
    task->chunkHashes = chunkHashes;
    task->seeders = seeders;

    // Store in global downloads list
    {
        lock_guard<mutex> lock(downloadsMutex);
        downloads.push_back(task);
    }

    // Capture variables needed after download for re-registration
    string capturedGroupId = groupId;
    string capturedFilePath = destPath;

    // Start download in background using shared_ptr (safe to copy)
    thread([task, capturedGroupId, capturedFilePath]() {
        string tempPath = task->destPath + ".downloading";
        int fd = open(tempPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            cerr << "Error: Cannot create destination file" << endl;
            return;
        }

        int numChunks = (int)task->chunkHashes.size();

        // Bounded parallel download: limit to at most 8 concurrent chunk threads
        // to avoid exhausting OS thread limits on large files.
        const int MAX_CONCURRENT = 8;
        int chunkIndex = 0;
        mutex indexMutex;

        auto workerFn = [&]() {
            while (true) {
                int myChunk;
                {
                    lock_guard<mutex> lk(indexMutex);
                    if (chunkIndex >= numChunks) return;
                    myChunk = chunkIndex++;
                }
                // Try each seeder until successful
                for (const auto &seeder : task->seeders) {
                    vector<string> parts = split(seeder, ':');
                    if (parts.size() != 2) continue;
                    
                    string peer_ip = parts[0];
                    int peer_port = stoi(parts[1]);
                    
                    vector<unsigned char> chunkData;
                    if (downloadChunkFromPeer(peer_ip, peer_port, task->groupId, 
                                             task->filename, myChunk, chunkData)) {
                        // Verify chunk hash
                        string downloadedHash = sha1sum(chunkData.data(), chunkData.size());
                        if (downloadedHash != task->chunkHashes[myChunk]) {
                            cerr << "Hash mismatch for chunk " << myChunk << ", retrying..." << endl;
                            continue;
                        }
                        
                        // Write chunk to file
                        lock_guard<mutex> taskLock(task->taskMutex);
                        if (lseek(fd, (off_t)myChunk * CHUNK_SIZE, SEEK_SET) < 0) {
                            cerr << "Seek error for chunk " << myChunk << endl;
                            continue;
                        }
                        
                        ssize_t written = write(fd, chunkData.data(), chunkData.size());
                        if (written == (ssize_t)chunkData.size()) {
                            task->downloadedBytes += written;
                            task->downloadedChunks[myChunk] = true;
                            cout << "Downloaded chunk " << myChunk << " from " << peer_ip << ":" << peer_port << endl;
                        }
                        break;
                    }
                }
            }
        };

        vector<thread> workers;
        int workerCount = min(MAX_CONCURRENT, numChunks);
        for (int w = 0; w < workerCount; w++) workers.emplace_back(workerFn);
        for (auto &t : workers) if (t.joinable()) t.join();
        
        close(fd);
        
        // Check if all chunks were downloaded successfully
        bool allChunksDownloaded = true;
        {
            lock_guard<mutex> taskLock(task->taskMutex);
            for (bool d : task->downloadedChunks) {
                if (!d) { allChunksDownloaded = false; break; }
            }
        }
        
        if (allChunksDownloaded) {
            // Rename temp file to final name
            if (rename(tempPath.c_str(), task->destPath.c_str()) == 0) {
                {
                    lock_guard<mutex> lock(task->taskMutex);
                    task->completed = true;
                }
                cout << "[C] [" << task->groupId << "] " << task->filename << " - Download completed" << endl;

                // Register the downloaded file in local path map so we can seed it
                {
                    lock_guard<mutex> lk(localFilesMutex);
                    localFilePaths[task->filename] = task->destPath;
                }

                // Notify tracker that we are now a seeder for this file.
                // Re-upload metadata so tracker adds us to seeders list.
                // We need hashes + real size: re-compute from the completed file.
                // This is done via the upload_file command with the completed file path.
                // (No separate "add_seeder" command exists; upload_file is idempotent.)
                long long realSize = getFileSize(task->destPath);
                string hashList;
                vector<string> hashes = task->chunkHashes;
                for (size_t i = 0; i < hashes.size(); i++) {
                    if (i > 0) hashList += ",";
                    hashList += hashes[i];
                }
                stringstream regCmd;
                regCmd << "upload_file " << task->groupId << " " << task->destPath
                       << " " << realSize << " " << hashList;
                sendCommand(regCmd.str()); // best-effort; ignore response
            } else {
                cerr << "Error: Failed to finalize download" << endl;
            }
        } else {
            cerr << "Error: Some chunks failed to download" << endl;
            unlink(tempPath.c_str()); // Delete incomplete file
        }
    }).detach();
    
    cout << "Download started for " << filename << endl;
}

// ------------------------ Download Management ------------------------
void showDownloads() {
    lock_guard<mutex> lock(downloadsMutex);
    
    if (downloads.empty()) {
        cout << "No active downloads" << endl;
        return;
    }
    
    cout << "Current downloads:" << endl;
    for (const auto &task : downloads) {
        double progress = 0.0;
        if (task->totalSize > 0) {
            progress = (double)task->downloadedBytes / task->totalSize * 100.0;
        }
        
        int downloadedChunks = count(task->downloadedChunks.begin(), task->downloadedChunks.end(), true);
        int totalChunks = task->downloadedChunks.size();
        
        cout << " - " << task->filename << " (Group: " << task->groupId << ")" << endl;
        cout << "   Progress: " << downloadedChunks << "/" << totalChunks << " chunks (" 
             << fixed << setprecision(1) << progress << "%)" << endl;
        cout << "   Status: " << (task->completed ? "Completed" : "In progress") << endl;
        cout << "   Size: " << task->downloadedBytes << "/" << task->totalSize << " bytes" << endl;
    }
}

// ------------------------ Tracker Management ------------------------
void loadTrackers(const string &filename) {
    trackers.clear();
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open tracker file");
        exit(1);
    }

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        perror("read tracker file");
        close(fd);
        exit(1);
    }
    buf[n] = '\0';
    close(fd);

    char *line = strtok(buf, "\n");
    while (line) {
        char id[64], ip[64];
        int client_port, sync_port;
        if (sscanf(line, "%s %s %d %d", id, ip, &client_port, &sync_port) == 4) {
            trackers.push_back({ip, client_port, id});
        }
        line = strtok(nullptr, "\n");
    }
    
    if (trackers.empty()) {
        cerr << "Error: No trackers found in file" << endl;
        exit(1);
    }
}

// ------------------------ Command Processing ------------------------
void processCommand(const string &cmd) {
    if (cmd.empty()) return;

    if (cmd == "show_downloads") {
        showDownloads();
        return;
    }

    if (cmd == "quit" || cmd == "exit") {
        // Cleanup will happen in main
        return;
    }

    // Handle download_file command separately
    if (cmd.find("download_file ") == 0) {
        stringstream ss(cmd);
        string action, groupId, filename, destPath;
        ss >> action >> groupId >> filename >> destPath;
        
        if (groupId.empty() || filename.empty() || destPath.empty()) {
            cout << "Usage: download_file <group_id> <file_name> <destination_path>" << endl;
            return;
        }
        
        downloadFile(groupId, filename, destPath);
        return;
    }

    // Handle upload_file command separately
    if (cmd.find("upload_file ") == 0) {
        stringstream ss(cmd);
        string action, groupId, filePath;
        ss >> action >> groupId >> filePath;
        
        if (groupId.empty() || filePath.empty()) {
            cout << "Usage: upload_file <group_id> <file_path>" << endl;
            return;
        }
        
        uploadFile(groupId, filePath);
        return;
    }

    // Intercept 'login' to append our seeding port before forwarding.
    // Original format:  login <uid> <pwd>
    // Sent to tracker:  login <uid> <pwd> <seed_port>
    // The tracker stores seed_port as the address other peers connect to.
    string actualCmd = cmd;
    if (cmd.find("login ") == 0) {
        actualCmd = cmd + " " + to_string(client_port);
    }

    // Send other commands to tracker
    string response = sendCommand(actualCmd);
    cout << response;

    // Track login/logout state locally so current_user stays in sync
    if (cmd.find("login ") == 0 && response.find("Login successful") != string::npos) {
        stringstream ss(cmd);
        string action, uid;
        ss >> action >> uid;
        current_user = uid;
    } else if ((cmd == "logout" || cmd.find("logout") == 0) &&
               response.find("Logout successful") != string::npos) {
        current_user.clear();
    }
    
    // If command failed due to tracker disconnect, try to reconnect and resend
    if (response.find("Error: Cannot connect") != string::npos || 
        response.find("Error: No response") != string::npos) {
        cout << "Attempting to reconnect..." << endl;
        if (establishConnection()) {
            response = sendCommand(cmd);
            cout << response;
        }
    }
}

// ------------------------ Main ------------------------
int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: ./client <IP>:<PORT> tracker_info.txt" << endl;
        cerr << "  <IP>:<PORT>  is YOUR OWN seeding address (e.g. 127.0.0.1:9000)" << endl;
        cerr << "Example: ./client 127.0.0.1:9000 trackerinfo.txt" << endl;
        return 1;
    }

    // Suppress SIGPIPE so that writes to closed sockets return EPIPE instead of
    // killing the process, allowing graceful reconnection logic to run.
    signal(SIGPIPE, SIG_IGN);

    // Parse this client's own seeding IP and port (the peer server listen address)
    string client_addr = argv[1];
    size_t colon_pos = client_addr.find(':');
    if (colon_pos == string::npos) {
        cerr << "Error: Invalid address format. Use <IP>:<PORT>" << endl;
        return 1;
    }
    
    client_ip = client_addr.substr(0, colon_pos);
    client_port = stoi(client_addr.substr(colon_pos + 1));
    
    string tracker_info_file = argv[2];
    
    // Load trackers
    loadTrackers(tracker_info_file);
    
    // Establish connection to tracker
    if (!establishConnection()) {
        cerr << "Error: Could not connect to any tracker" << endl;
        return 1;
    }

    // Start peer seeding service on our declared port BEFORE any login so the
    // port is ready when the tracker advertises us to other peers.
    thread(startSeedingService, client_port).detach();
    
    cout << "Client started. Seeding on " << client_ip << ":" << client_port << endl;
    cout << "Type 'help' for available commands" << endl;

    // Main command loop
    string cmd;
    while (true) {
        cout << "> ";
        if (!getline(cin, cmd)) {
            break;
        }
        
        if (cmd == "quit" || cmd == "exit") {
            break;
        }
        
        if (cmd == "help") {
            cout << "Available commands:" << endl;
            cout << "  create_user <user_id> <password>" << endl;
            cout << "  login <user_id> <password>" << endl;
            cout << "  logout" << endl;
            cout << "  create_group <group_id>" << endl;
            cout << "  join_group <group_id>" << endl;
            cout << "  leave_group <group_id>" << endl;
            cout << "  list_groups" << endl;
            cout << "  list_requests <group_id>" << endl;
            cout << "  accept_request <group_id> <user_id>" << endl;
            cout << "  upload_file <group_id> <file_path>" << endl;
            cout << "  list_files <group_id>" << endl;
            cout << "  download_file <group_id> <file_name> <destination_path>" << endl;
            cout << "  stop_share <group_id> <file_name>" << endl;
            cout << "  show_downloads" << endl;
            cout << "  quit" << endl;
            continue;
        }
        
        processCommand(cmd);
    }

    // Cleanup
    is_seeding = false;
    if (peer_server_socket >= 0) {
        close(peer_server_socket);
    }
    if (tracker_sock >= 0) {
        // Auto-logout so the tracker marks us offline and removes us from seeders
        if (!current_user.empty()) {
            sendCommand("logout");
            current_user.clear();
        }
        close(tracker_sock);
    }
    
    cout << "Client shutdown complete" << endl;
    return 0;
}