// /opt/backup_daemon
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

std::map<std::string, std::string> config;
bool isDaemonRunning = false;
std::string configPath = "/opt/backup_daemon/backup_config.ini";
std::string pidFilePath = "/var/run/backup_daemon.pid";

int createBackup(const std::string& sourceDir, const std::string& backupDir) {
    time_t now = time(nullptr);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", localtime(&now));

    std::string destination = backupDir + "/backup_" + timestamp;

    if (mkdir(destination.c_str(), 0755) != 0 && errno != EEXIST) {
        syslog(LOG_ERR, "Failed to create backup directory: %s", strerror(errno));
        return 1;
    }

    std::string rsyncCmd = "rsync -av --exclude=/dev --exclude=/proc --exclude=/sys --exclude=/mnt --exclude=/lost+found "
                      + sourceDir + "/ " + destination + "/";

    FILE* pipe = popen(rsyncCmd.c_str(), "r");
    if (!pipe) {
        syslog(LOG_ERR, "Error opening pipe: %s", strerror(errno));
        return 1;
    }

    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    int returnCode = pclose(pipe);

    if (returnCode != 0) {
        syslog(LOG_ERR, "Error running rsync: %s", result.c_str());
        return 1;
    }

    syslog(LOG_INFO, "Backup created successfully at %s", destination.c_str());
    return 0;
}

void daemonLoop(const std::string& configPath) {
    openlog("BackupDaemon", LOG_PID, LOG_DAEMON);
    while (true) {
        readConfig(configPath);

        if (config.empty()) {
            syslog(LOG_ERR, "Configuration is invalid or empty.");
            break;
        }

        std::string sourceDir = config["source_dir"];
        std::string backupDir = config["backup_dir"];
        int backupFrequencyMinutes = std::stoi(config["backup_frequency_minutes"]);

        int result = createBackup(sourceDir, backupDir);
        if (result != 0) {
            syslog(LOG_ERR, "Backup failed.");
        }

        std::this_thread::sleep_for(std::chrono::minutes(backupFrequencyMinutes));
    }
    closelog();
}

void getStatus() {
    int pid = readPIDFromFile();
    if (pid != -1 && kill(pid, 0) == 0) {
        syslog(LOG_INFO, "Daemon is running (PID: %d).", pid);
    } else {
        syslog(LOG_INFO, "Daemon is not running.");
    }
}

void readConfig(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        syslog(LOG_ERR, "Failed to open config file: %s", filePath.c_str());
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t equalsPos = line.find('=');
        if (equalsPos != std::string::npos) {
            std::string key = line.substr(0, equalsPos);
            std::string value = line.substr(equalsPos + 1);
            config[key] = value;
        }
    }

    file.close();
}

int readPIDFromFile() {
    int pid = -1;
    std::ifstream pidFile(pidFilePath);
    if (pidFile.is_open()) {
        pidFile >> pid;
        pidFile.close();
    }
    return pid;
}

void savePIDToFile() {
    std::ofstream pidFile(pidFilePath);
    if (pidFile.is_open()) {
        pidFile << getpid();
        pidFile.close();
    }
}

void startDaemon() {
    pid_t pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork process.");
        exit(1);
    }

    if (pid > 0) {
        exit(0);
    }

    umask(0);
    if (setsid() < 0) {
        syslog(LOG_ERR, "Failed to create new session.");
        exit(1);
    }

    if (chdir("/") < 0) {
        syslog(LOG_ERR, "Failed to change directory.");
        exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    savePIDToFile();
    isDaemonRunning = true;
    syslog(LOG_INFO, "Daemon started.");

    daemonLoop(configPath);
}

void stopDaemon() {
    int pid = readPIDFromFile();
    if (pid != -1) {
        if (kill(pid, SIGTERM) == 0) {
            syslog(LOG_INFO, "Daemon stopped.");
            remove(pidFilePath.c_str());
        } else {
            syslog(LOG_ERR, "Failed to stop daemon: %s", strerror(errno));
        }
    } else {
        syslog(LOG_INFO, "Daemon is not running.");
    }
}

int main(int argc, char* argv[]) {
    openlog("BackupDaemon", LOG_PID, LOG_DAEMON);

    if (argc < 2) {
        syslog(LOG_ERR, "Usage: %s <start|stop|status>", argv[0]);
        closelog();
        return 1;
    }

    std::string command = argv[1];

    if (command == "start") {
        startDaemon();
    } else if (command == "stop") {
        stopDaemon();
    } else if (command == "status") {
        getStatus();
    } else {
        syslog(LOG_ERR, "Unknown command: %s", command.c_str());
    }

    closelog();
    return 0;
}

