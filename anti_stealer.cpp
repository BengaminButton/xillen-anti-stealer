#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <map>

class XillenAntiStealer {
private:
    std::vector<std::string> suspicious_processes;
    std::vector<std::string> suspicious_windows;
    std::vector<std::string> suspicious_registry_keys;
    std::map<std::string, std::string> detected_threats;
    bool monitoring_active;
    
public:
    XillenAntiStealer() : monitoring_active(false) {
        initialize_suspicious_patterns();
    }
    
    void initialize_suspicious_patterns() {
        suspicious_processes = {
            "keylogger.exe", "stealer.exe", "rat.exe", "spy.exe",
            "hook.dll", "inject.dll", "capture.dll", "monitor.dll",
            "ahk.exe", "autohotkey.exe", "macro.exe", "recorder.exe"
        };
        
        suspicious_windows = {
            "Keylogger", "Stealer", "RAT", "Spy", "Hook",
            "Capture", "Monitor", "Recorder", "Macro"
        };
        
        suspicious_registry_keys = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"
        };
    }
    
    bool is_process_suspicious(const std::string& process_name) {
        std::string lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        for (const auto& suspicious : suspicious_processes) {
            if (lower_name.find(suspicious) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    bool is_window_suspicious(const std::string& window_title) {
        std::string lower_title = window_title;
        std::transform(lower_title.begin(), lower_title.end(), lower_title.begin(), ::tolower);
        
        for (const auto& suspicious : suspicious_windows) {
            std::string lower_suspicious = suspicious;
            std::transform(lower_suspicious.begin(), lower_suspicious.end(), lower_suspicious.begin(), ::tolower);
            
            if (lower_title.find(lower_suspicious) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    std::vector<std::string> get_running_processes() {
        std::vector<std::string> processes;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    processes.push_back(std::string(pe32.szExeFile));
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
        
        return processes;
    }
    
    std::vector<std::string> get_visible_windows() {
        std::vector<std::string> windows;
        
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            if (IsWindowVisible(hwnd)) {
                char title[256];
                GetWindowTextA(hwnd, title, sizeof(title));
                
                if (strlen(title) > 0) {
                    std::vector<std::string>* windows = reinterpret_cast<std::vector<std::string>*>(lParam);
                    windows->push_back(std::string(title));
                }
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&windows));
        
        return windows;
    }
    
    bool check_registry_persistence() {
        HKEY hkey;
        bool suspicious_found = false;
        
        for (const auto& key_path : suspicious_registry_keys) {
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path.c_str(), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
                char value_name[256];
                DWORD value_name_size = sizeof(value_name);
                DWORD index = 0;
                
                while (RegEnumValueA(hkey, index, value_name, &value_name_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::string value = value_name;
                    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                    
                    if (value.find("stealer") != std::string::npos || 
                        value.find("keylogger") != std::string::npos ||
                        value.find("rat") != std::string::npos) {
                        
                        detected_threats["Registry"] = "Suspicious registry value: " + std::string(value_name);
                        suspicious_found = true;
                    }
                    
                    value_name_size = sizeof(value_name);
                    index++;
                }
                RegCloseKey(hkey);
            }
        }
        
        return suspicious_found;
    }
    
    bool check_file_system() {
        std::vector<std::string> suspicious_paths = {
            "C:\\temp\\", "C:\\temp2\\", "C:\\users\\public\\",
            "C:\\programdata\\", "C:\\windows\\temp\\"
        };
        
        bool suspicious_found = false;
        
        for (const auto& path : suspicious_paths) {
            WIN32_FIND_DATAA find_data;
            HANDLE find_handle = FindFirstFileA((path + "*").c_str(), &find_data);
            
            if (find_handle != INVALID_HANDLE_VALUE) {
                do {
                    std::string filename = find_data.cFileName;
                    std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
                    
                    if (filename.find("stealer") != std::string::npos ||
                        filename.find("keylogger") != std::string::npos ||
                        filename.find("rat") != std::string::npos ||
                        filename.find("hook") != std::string::npos) {
                        
                        detected_threats["FileSystem"] = "Suspicious file: " + path + find_data.cFileName;
                        suspicious_found = true;
                    }
                } while (FindNextFileA(find_handle, &find_data));
                FindClose(find_handle);
            }
        }
        
        return suspicious_found;
    }
    
    bool check_network_connections() {
        bool suspicious_found = false;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPNET, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE) {
            MIB_TCPROW_OWNER_PID* tcp_table;
            DWORD table_size = 0;
            
            if (GetExtendedTcpTable(NULL, &table_size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
                tcp_table = (MIB_TCPROW_OWNER_PID*)malloc(table_size);
                
                if (GetExtendedTcpTable(tcp_table, &table_size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    DWORD num_entries = table_size / sizeof(MIB_TCPROW_OWNER_PID);
                    
                    for (DWORD i = 0; i < num_entries; i++) {
                        if (tcp_table[i].dwLocalPort == 4444 || 
                            tcp_table[i].dwLocalPort == 8080 ||
                            tcp_table[i].dwLocalPort == 1337) {
                            
                            detected_threats["Network"] = "Suspicious port: " + std::to_string(tcp_table[i].dwLocalPort);
                            suspicious_found = true;
                        }
                    }
                }
                free(tcp_table);
            }
            CloseHandle(snapshot);
        }
        
        return suspicious_found;
    }
    
    void scan_system() {
        std::cout << "[+] Starting XILLEN Anti-Stealer scan..." << std::endl;
        
        bool threats_detected = false;
        
        std::cout << "[+] Scanning running processes..." << std::endl;
        auto processes = get_running_processes();
        for (const auto& process : processes) {
            if (is_process_suspicious(process)) {
                detected_threats["Process"] = "Suspicious process: " + process;
                threats_detected = true;
                std::cout << "[-] Suspicious process detected: " << process << std::endl;
            }
        }
        
        std::cout << "[+] Scanning visible windows..." << std::endl;
        auto windows = get_visible_windows();
        for (const auto& window : windows) {
            if (is_window_suspicious(window)) {
                detected_threats["Window"] = "Suspicious window: " + window;
                threats_detected = true;
                std::cout << "[-] Suspicious window detected: " << window << std::endl;
            }
        }
        
        std::cout << "[+] Checking registry persistence..." << std::endl;
        if (check_registry_persistence()) {
            threats_detected = true;
        }
        
        std::cout << "[+] Checking file system..." << std::endl;
        if (check_file_system()) {
            threats_detected = true;
        }
        
        std::cout << "[+] Checking network connections..." << std::endl;
        if (check_network_connections()) {
            threats_detected = true;
        }
        
        if (threats_detected) {
            std::cout << "\n[!] THREATS DETECTED!" << std::endl;
            std::cout << "================================" << std::endl;
            for (const auto& threat : detected_threats) {
                std::cout << "[" << threat.first << "] " << threat.second << std::endl;
            }
        } else {
            std::cout << "\n[+] No threats detected. System appears clean." << std::endl;
        }
    }
    
    void start_monitoring() {
        if (monitoring_active) {
            std::cout << "[-] Monitoring already active" << std::endl;
            return;
        }
        
        monitoring_active = true;
        std::cout << "[+] Starting continuous monitoring..." << std::endl;
        
        std::thread monitor_thread([this]() {
            while (monitoring_active) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                
                auto processes = get_running_processes();
                for (const auto& process : processes) {
                    if (is_process_suspicious(process)) {
                        std::cout << "[!] NEW THREAT DETECTED: " << process << std::endl;
                        detected_threats["Process"] = "Suspicious process: " + process;
                    }
                }
                
                if (check_registry_persistence()) {
                    std::cout << "[!] NEW REGISTRY THREAT DETECTED!" << std::endl;
                }
            }
        });
        
        monitor_thread.detach();
    }
    
    void stop_monitoring() {
        monitoring_active = false;
        std::cout << "[+] Monitoring stopped" << std::endl;
    }
    
    void save_report(const std::string& filename) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "XILLEN Anti-Stealer Report" << std::endl;
            file << "==========================" << std::endl;
            file << "Scan completed at: " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            file << std::endl;
            
            if (detected_threats.empty()) {
                file << "No threats detected." << std::endl;
            } else {
                file << "Detected threats:" << std::endl;
                for (const auto& threat : detected_threats) {
                    file << "[" << threat.first << "] " << threat.second << std::endl;
                }
            }
            
            file.close();
            std::cout << "[+] Report saved to: " << filename << std::endl;
        } else {
            std::cout << "[-] Failed to save report" << std::endl;
        }
    }
};

int main() {
    SetConsoleOutputCP(CP_UTF8);
    
    std::cout << "=========================================" << std::endl;
    std::cout << "    XILLEN Anti-Stealer v1.0" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << std::endl;
    
    XillenAntiStealer anti_stealer;
    
    char choice;
    do {
        std::cout << "Select option:" << std::endl;
        std::cout << "1. Scan system" << std::endl;
        std::cout << "2. Start monitoring" << std::endl;
        std::cout << "3. Stop monitoring" << std::endl;
        std::cout << "4. Save report" << std::endl;
        std::cout << "5. Exit" << std::endl;
        std::cout << "Choice: ";
        std::cin >> choice;
        
        switch (choice) {
            case '1':
                anti_stealer.scan_system();
                break;
            case '2':
                anti_stealer.start_monitoring();
                break;
            case '3':
                anti_stealer.stop_monitoring();
                break;
            case '4':
                anti_stealer.save_report("anti_stealer_report.txt");
                break;
            case '5':
                std::cout << "[+] Exiting..." << std::endl;
                break;
            default:
                std::cout << "[-] Invalid choice" << std::endl;
        }
        
        std::cout << std::endl;
    } while (choice != '5');
    
    return 0;
}
