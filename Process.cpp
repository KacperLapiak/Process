////////////////////////////////////////////// Process (class) //////////////////////////////////////////////////
// MSDN documentatnion for used functions:                                                                     //
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess       //
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken  //
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges //
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea                 //
//                                                                                                             //
//                                                                                                             //
// CAUTION: The UAC has to be turned off and you have to run this program with adminsitrator rights.           //
// ----------------------------------------------------------------------------------------------------------- //
// Problem: You can't read a memory belonging to lots of other processes from builded .exe program.            //
// Solution: This class solved this problemm, and privde more usefull functions.                               //
// Used environment: Visual Studio Community 2019                                                              //
// This code has to be build in x64 mode.                                                                      //
// ----------------------------------------------------------------------------------------------------------- //
// This class let you:                                                                                         //
// 1. Open all processes running that are visible for user.                                                    //
// 2. Get all processes running that are visible for user.                                                     //
// 3. Get all processes name that are visible for user.                                                        //
// 4. Read memory of specific process.                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <psapi.h>
#include <vector>
#include <memory>
#include <string>
#include <iostream>

using namespace std;

class Process
{
public:
    int procsNumber_;
    SIZE_T readBytes_ = 0;
    unique_ptr<DWORD[]> procsPid_{ new DWORD[procsNumber_] };
    unique_ptr<string[]> procsName_{ new string[procsNumber_] };
    unique_ptr<HANDLE[]> hProcs_{ new HANDLE[procsNumber_] };
    vector<char> bytesBuffer_;

    Process() : procsNumber_(getProcsNumb())
    {
        getProcsPid();
        getProcsName();
    }

    int getProcsNumb()
    {
        // Get the list of process identifiers.
        DWORD procsIdTemp[1024], cbNeeded;
        EnumProcesses(procsIdTemp, sizeof(procsIdTemp), &cbNeeded);

        // Calculate how many process identifiers were returned.
        return cbNeeded / sizeof(DWORD);
    }
    void getProcsPid()
    {
        // Get the list of process identifiers.
        DWORD procsIdTemp[512], cbNeeded;
        EnumProcesses(procsIdTemp, sizeof(procsIdTemp), &cbNeeded);

        // Rewrite processes ID to extern table.
        for (int i = 0; i < procsNumber_; i++)
            procsPid_[i] = procsIdTemp[i];
    }
    void openProcs()
    {
        // assumption: there is not more than 200 running processes
        HANDLE hToken[200];
        TOKEN_PRIVILEGES newState[200];
        LUID luid[200];

        // Open all processes.
        for (int i = 0; i < procsNumber_; i++)
        {
            LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid[i]);

            newState[i].PrivilegeCount = 1;
            newState[i].Privileges[0].Luid = luid[i];
            newState[i].Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            hProcs_[i] = OpenProcess(PROCESS_ALL_ACCESS, TRUE, procsPid_[i]);

            OpenProcessToken(hProcs_[i], TOKEN_ALL_ACCESS, &hToken[i]);
            AdjustTokenPrivileges(hToken[i], FALSE, &newState[i], sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
        }
    }
    void closeProcs()
    {
        // Close all processes.
        for (int i = 0; i < procsNumber_; i++)
            CloseHandle(hProcs_[i]);
    }
    void getProcsName()
    {
        openProcs();

        HMODULE hMod;
        DWORD cbNeeded;

        for (int i = 0; i < procsNumber_; i++)
        {
            TCHAR bufName[40]{};
            EnumProcessModules(hProcs_[i], &hMod, sizeof(hMod), &cbNeeded);
            GetModuleBaseName(hProcs_[i], hMod, bufName, sizeof(bufName) / sizeof(TCHAR));

            for (int a = 0; a < sizeof(bufName) / sizeof(TCHAR); a++)
                procsName_[i] += bufName[a];
        }

        closeProcs();
    }
    void readProcMem(int pid, int bytes, int startAddress)
    {
        // assumption: one data portion not greater than 2048 bytes
        char buf[2048]{};
        bytesBuffer_.clear();

        // create handle for process
        HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

        // find first byte ready to read
        while (ReadProcessMemory(hproc, (void*)startAddress, buf, bytes, NULL) == 0) startAddress++;

        // read memory from first byte ready to read
        ReadProcessMemory(hproc, (void*)startAddress, buf, bytes, &readBytes_);

        // save the bytes
        for (int i = 0; i < readBytes_; i++)
            bytesBuffer_.push_back(buf[i]);

        CloseHandle(hproc);
    }
};

int main()
{
    Process inst;

    // Print pid's and processes name.
    for (int i = 0; i < inst.procsNumber_; i++)
    {
        cout.width(6);
        cout << inst.procsPid_[i];
        cout << " " << inst.procsName_[i] << endl;
    }

    // Print first 100 bytes that belongs to specific process.
    // Check bytes from 0x00000001 and find first readable, then read from here.
    inst.readProcMem(inst.procsPid_[10], 100, 0x00000001);
    for (int i = 0; i < 100; i++)
        cout << inst.bytesBuffer_[i];

    cin.get();

    return 0;
}