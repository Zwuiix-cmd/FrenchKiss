#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <conio.h>
#include <random>
#include <iomanip>
#include <chrono>
#include <memory>
#include <thread>
#include <mutex>

DWORD processId;
HANDLE handle;

bool status = false;

void* showPlayerNametag;
void* forceShowNametags;

std::mutex resultsMutex;
std::vector<std::pair<std::string, void*>> results;

HANDLE GetProcessByName(const PCSTR name)
{
    DWORD pid = 0;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (std::string(process.szExeFile) == std::string(name))
            {
                pid = process.th32ProcessID;
                processId = pid;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    }

    return nullptr;
}

std::vector<void*> scanString(const std::string& searchString) {
    std::vector<void*> foundAddresses;
    MEMORY_BASIC_INFORMATION memInfo;
    void* currentAddress = 0;

    while (VirtualQueryEx(handle, currentAddress, &memInfo, sizeof(memInfo)) != 0) {
        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
            std::vector<char> pageData(memInfo.RegionSize);

            SIZE_T bytesRead;
            if (ReadProcessMemory(handle, currentAddress, pageData.data(), memInfo.RegionSize, &bytesRead)) {
                std::string pageString(pageData.begin(), pageData.end());

                size_t pos = 0;
                while ((pos = pageString.find(searchString, pos)) != std::string::npos) {
                    foundAddresses.push_back(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(currentAddress) + pos));
                    pos += searchString.length();
                }
            }
        }

        currentAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(currentAddress) + memInfo.RegionSize);
    }

    return foundAddresses;
}

void patchBytes(void* dst, void* src, unsigned int size) {
    DWORD oldprotect;
    VirtualProtectEx(handle, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    WriteProcessMemory(handle, dst, src, size, 0);
    VirtualProtectEx(handle, dst, size, oldprotect, &oldprotect);
};

bool compareBytes(const BYTE* data, const BYTE* pattern, const char* mask) {
    for (; *mask; ++mask, ++data, ++pattern) {
        if (*mask == 'x' && *data != *pattern) {
            return false;
        }
    }
    return (*mask) == 0;
}

struct Pattern {
    std::vector<BYTE> bytes;
    std::string mask;
};

void scanMemory(HANDLE handle, void* startAddress, SIZE_T regionSize, const std::vector<Pattern>& patterns, const std::vector<std::string>& sigs, int& finded) {
    std::unique_ptr<BYTE[]> pageData(new BYTE[regionSize]);
    SIZE_T bytesRead;
    if (ReadProcessMemory(handle, startAddress, pageData.get(), regionSize, &bytesRead)) {
        for (const auto& pattern : patterns) {
            const BYTE* patBytes = pattern.bytes.data();
            const char* patMask = pattern.mask.c_str();

            for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i) {
                if (compareBytes(pageData.get() + i, patBytes, patMask)) {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    results.push_back(std::make_pair(sigs[&pattern - &patterns[0]], reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(startAddress) + i)));
                    finded++;
                    if (finded >= sigs.size()) return;
                }
            }
        }
    }
}

void scanSigs() {
    std::vector<std::string> sigs = {
            "0F 84 95 03 00 00 49 8B D6 48 8B",
            "0F 84 82 03 00 00 49 8D 97 E0 00"
    };

    int finded = 0;

    std::vector<Pattern> patterns;
    for (const auto& sig : sigs) {
        Pattern pattern;
        const char* str = sig.c_str();
        while (*str) {
            if (*str == ' ') {
                ++str;
                continue;
            }
            if (*str == '?') {
                pattern.bytes.push_back(0);
                pattern.mask.push_back('?');
                ++str;
                if (*str == '?') {
                    ++str;
                }
            } else {
                pattern.bytes.push_back(static_cast<BYTE>(std::strtoul(str, nullptr, 16)));
                pattern.mask.push_back('x');
                while (*str && *str != ' ') {
                    ++str;
                }
            }
        }
        patterns.push_back(pattern);
    }

    MEMORY_BASIC_INFORMATION memInfo;
    void* currentAddress = nullptr;

    std::vector<std::thread> threads;

    while (VirtualQueryEx(handle, currentAddress, &memInfo, sizeof(memInfo)) != 0) {
        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
            threads.emplace_back(scanMemory, handle, currentAddress, memInfo.RegionSize, std::ref(patterns), std::ref(sigs), std::ref(finded));
            if (finded >= sigs.size()) break;
        }
        currentAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(currentAddress) + memInfo.RegionSize);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (const auto& element : results) {
        if (element.first == "0F 84 95 03 00 00 49 8B D6 48 8B") showPlayerNametag = element.second;
        if (element.first == "0F 84 82 03 00 00 49 8D 97 E0 00") forceShowNametags = element.second;
    }
}

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
void InstallHook();
void UninstallHook();

HHOOK hHook = nullptr;

void InstallHook() {
    hHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, nullptr, 0);
    if (hHook == nullptr) {
        std::cerr << "Failed to install hook!" << std::endl;
    } else {
        std::cout << "Hook installed successfully!" << std::endl;
    }
}

void UninstallHook() {
    if (hHook != nullptr) {
        UnhookWindowsHookEx(hHook);
        std::cout << "Hook uninstalled successfully!" << std::endl;
    }
}

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        auto* pMouse = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);

        switch (wParam) {
            case WM_XBUTTONDOWN:
                if (HIWORD(pMouse->mouseData) == XBUTTON1) {
                    status = !status;
                    if(status) {
                        BYTE bytes[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                        patchBytes(showPlayerNametag, bytes, sizeof(bytes));
                        patchBytes(forceShowNametags, bytes, sizeof(bytes));
                    } else {
                        BYTE bytes1[] = {0x0F, 0x84 , 0x95, 0x03, 0x00, 0x00, 0x49, 0x8B, 0xD6, 0x48, 0x8B};
                        patchBytes(showPlayerNametag, &bytes1, sizeof(bytes1));
                        BYTE bytes2[] = {0x0F, 0x84, 0x82, 0x03, 0x00, 0x00, 0x49, 0x8D, 0x97, 0xE0, 0x00};
                        patchBytes(forceShowNametags, bytes2, sizeof(bytes2));
                    }
                } else if (HIWORD(pMouse->mouseData) == XBUTTON2) {
                }
                break;
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

void start()
{
    InstallHook();

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UninstallHook();
}

int main() {
    handle = GetProcessByName("Minecraft.Windows.exe");
    if(handle == nullptr) {
        std::cout << "Failed to find Minecraft.Windows.exe" << std::endl;
        Sleep(10000);
        return 0;
    }

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);

    auto st = std::chrono::high_resolution_clock::now();
    scanSigs();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - st;
    std::cout << "Scan took " << duration.count() << " seconds." << std::endl; // My old code took 40s now this one takes 10s

    void* sigNameTag = showPlayerNametag;
    if(sigNameTag == nullptr) {
        std::cout << "Not found ShowPlayerNameTag sig" << std::endl;
        Sleep(30000);
        return 0;
    }

    void* sigForceNameTag = forceShowNametags;
    if(sigForceNameTag == nullptr) {
        std::cout << "Not found ForceShowPlayerNametag sig" << std::endl;
        Sleep(30000);
        return 0;
    }
    std::cout << "All the sigs have been found!" << std::endl;

    start();
    return 0;
}