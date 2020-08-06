/* Copyright (C) 2020 FireEye, Inc. All Rights Reserved. */ 

#define WIN32_LEAN_AND_MEAN
#include "jitmhook.h"
#include <wincrypt.h>
#include <shlwapi.h>

#include "modules.h"
#include "CDNet.h"

#include <polyhook2/ErrorLog.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>

#ifdef _WIN64
#include <polyhook2/Detour/x64Detour.hpp>
#define GDetour x64Detour
#define Arch Mode::x64
#else
#include <polyhook2/Detour/x86Detour.hpp>
#define GDetour x86Detour
#define Arch Mode::x86
#endif

#include <memory>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Shlwapi.lib")
#define JSON_FILENAME "jitm.json"
#define LOG_FILENAME  "jitm.log"

uint64_t                    origCompileMethod = 0;
PLH::CapstoneDisassembler   gDis(PLH::Arch);
std::shared_ptr<PLH::IHook> gHook;

CRITICAL_SECTION            gCS;
std::ofstream               gJson;
std::ofstream               gLog;
DWORD                       gCount;
BOOL                        gbHooked = false;
PVOID                       gpTarget = (PVOID)0x41414141;    // dummy target
HMODULE                     hModuleTarget = NULL;
std::string                 gsTarget;
std::string                 gsTargetFilename;
std::string                 gsTargetName;
CDNet                       gCDNet;
std::map<DWORD, PMethod>    gMethods;


/******************************************************************************
 * UTILITIES
 *****************************************************************************/
PMethod FindMethodByToken(DWORD nToken)
{
    std::map<DWORD, PMethod>::iterator it = gMethods.find(nToken);
    if (it == gMethods.end())
        return NULL;
    return it->second;
}


BOOL Base64Encode(std::vector<BYTE> bytes, std::string &out)
{
    char *encoded = NULL;
    DWORD nEncodedSize = 0;
    CryptBinaryToStringA(
        bytes.data(),
        bytes.size(),
        CRYPT_STRING_BASE64,
        NULL,
        &nEncodedSize);
    encoded = (CHAR *)VirtualAlloc(
        NULL,
        nEncodedSize + 1,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    memset(encoded, 0, nEncodedSize + 1);
    CryptBinaryToStringA(
        bytes.data(),
        bytes.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        encoded,
        &nEncodedSize);
    out.assign(encoded, nEncodedSize);
    VirtualFree(encoded, nEncodedSize, MEM_RELEASE);
    return TRUE;
}


VOID GenJSONEntry(PMethod method, std::string &sJsonEntry)
{
    std::ostringstream oss;
    oss << "{"
        << "\"nToken\":" << method->nToken << ","
        << "\"sHeader\":\"" << method->sHeader << "\","
        << "\"sBody\":\"" << method->sBody << "\""
        << "}";
    std::string s = oss.str();
    sJsonEntry.clear();
    sJsonEntry.assign(s.c_str(), s.size());
    return;
}


BOOL WriteMethodsAndHeaders()
{
    std::cout << "[*] Looking for module: " << gsTargetFilename.c_str() << std::endl;
    DWORD pImageBase = (DWORD)FindModuleByName(gsTargetFilename.c_str());
    std::cout << "[*] Target image base: 0x" << std::hex << pImageBase << std::dec << std::endl;

    gJson.open(JSON_FILENAME);
    gJson << "[";
    int nCount = 0;
    std::map<DWORD, PMethod>::iterator it;
    for (it = gMethods.begin(); it != gMethods.end(); ++it)
    {
        PMethod method = it->second;
        MethodDef *md = gCDNet.FindMethodDefByToken(method->nToken);
        if (pImageBase && md)
        {
            PBYTE pNewHdr = ((PBYTE)((DWORD)pImageBase + md->nRVA));
            SIZE_T nBodySize = method->RawBody.size();
            BYTE bHdr = *pNewHdr;
            std::vector <BYTE> newHeader;
            newHeader.clear();
            BOOL isTiny = ((bHdr & 3) == 2);
            // Update the size field of the method body header
            if (isTiny)
            {
                // For a tiny header, the entire method body header is 1 byte long:
                // - Least significant 2 bits must be 10 (or 2 in decimal)
                // - 6 most significant bits indicate the size of the MSIL
                BYTE b = *pNewHdr;
                b = (BYTE)(((nBodySize & 0xFFFFFF) << 2) + 2);
                method->RawHeader.push_back(b);
            }
            else
            {
                // For a fat header, the entire method body heaeder is 0x0C bytes long
                // - The size field starts at offset 4
                // We can safely copy the rest

                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 0)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 1)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 2)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 3)));

                // Update MSIL Size here
                method->RawHeader.push_back(*((PBYTE)(&nBodySize) + 0));
                method->RawHeader.push_back(*((PBYTE)(&nBodySize) + 1));
                method->RawHeader.push_back(*((PBYTE)(&nBodySize) + 2));
                method->RawHeader.push_back(*((PBYTE)(&nBodySize) + 3));

                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 8)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 9)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 10)));
                method->RawHeader.push_back(*((PBYTE)((DWORD)pNewHdr + 11)));
            }
            Base64Encode(method->RawHeader, method->sHeader);
        }
        std::string  sJsonEntry;
        GenJSONEntry(method, sJsonEntry);

        if (nCount == 0)
            gJson << std::endl;
        else
            gJson << "," << std::endl;
        gJson << sJsonEntry.c_str();
        nCount += 1;
    }
    std::cout << "[*] Totally logged " << nCount << " methods" << std::endl;
    gJson << std::endl << "]" << std::endl;
    gJson.close();
    return true;
}

/**
 * Check if this method belong to the target assembly(executable) 
 */
BOOL IsTargetMethod(ICorJitInfo *comp, CORINFO_METHOD_INFO *info)
{
    DWORD nAddress = (DWORD)(info->ILCode);
    CORINFO_ASSEMBLY_HANDLE hAsm = comp->getModuleAssembly(info->scope);
    const char *pAsmName = comp->getAssemblyName(hAsm);
    mdMethodDef nToken = comp->getMethodDefFromMethod(info->ftn);
    if (strstr(pAsmName, gsTargetName.c_str()) == NULL)
    {
        //printf("[!] Skipping method 0x%x from %s, only care about %s\n",
        //    nToken, pAsmName, gsTargetName.c_str());
        gLog    << "[!] Skipping method 0x" << std::hex << nToken << std::dec
                << " from " << pAsmName << std::endl;
        return false;
    }
    //printf("[!] Logging 0x%x from %s\n", nToken, pAsmName);
    gLog    << "[!] Logging 0x" << std::hex << nToken << std::dec
            << " from " << pAsmName << std::endl;
    return true;
}

/**
 * Save the IL into a global list
 */
void SaveIL(ICorJitInfo *comp, CORINFO_METHOD_INFO *info)
{
    EnterCriticalSection(&gCS);
    DWORD nToken = comp->getMethodDefFromMethod(info->ftn);
    PMethod pm = FindMethodByToken(nToken);
    if (pm == NULL)
    {
        PMethod method = new Method();
        for (unsigned int i = 0; i < info->ILCodeSize; i++)
            method->RawBody.push_back(*(info->ILCode + i));
        method->nToken = nToken;
        method->sBody.clear();
        Base64Encode(method->RawBody, method->sBody);
        gMethods.insert(std::pair<DWORD, PMethod>(nToken, method));
    }
    LeaveCriticalSection(&gCS);
    return;
}

/******************************************************************************
 * Hook related stuffs
 *****************************************************************************/
int __stdcall HandleCompileMethod(uintptr_t thisptr,
    ICorJitInfo *comp,
    CORINFO_METHOD_INFO *info,
    unsigned flags,
    BYTE **nativeEntry,
    ULONG *nativeSizeOfCode)
{
    if (IsTargetMethod(comp, info))
    {
        SaveIL(comp, info);
    }
    return 0;
}

int __stdcall MyCompileMethod(uintptr_t thisptr,
    ICorJitInfo *comp,
    CORINFO_METHOD_INFO *info,
    unsigned flags,
    BYTE **nativeEntry,
    ULONG *nativeSizeOfCode)
{
    HandleCompileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);
    return ((PCompileMethod)origCompileMethod)(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);
}

/******************************************************************************
 * EXPORTS
 *****************************************************************************/

/**
 * Init() should be called first thing to initialize the hook. It performs
 * the following tasks:
 * - Parse the target filename
 * - Open the logfile
 * - Parse the target .NET metadata
 */
extern "C" __declspec(dllexport) BOOL Init(char *pszFilename = NULL)
{
    EnterCriticalSection(&gCS);
    gsTarget.assign(pszFilename);

    CHAR szFilename[MAX_PATH] = { 0 };
    CHAR szExtension[MAX_PATH] = { 0 };
    _splitpath(pszFilename, NULL, NULL, szFilename, szExtension);
    gsTargetName.assign(szFilename);
    gsTargetFilename.append(szFilename);
    gsTargetFilename.append(szExtension);

    std::cout << "[*] Target is: " << gsTarget.c_str() << std::endl;
    std::cout << "[*] Filename is: " << gsTargetName.c_str() << std::endl;

    gCount = 0;
    gLog.open(LOG_FILENAME);
    gCDNet.Initialize(gsTarget.c_str());
    gCDNet.Parse();

    LeaveCriticalSection(&gCS);
    return true;
}

/**
 * Install a hook to process the IL inline before calling compileMethod()
 */
extern "C" __declspec(dllexport) BOOL Hook()
{
    if (gbHooked)
        return TRUE;

    // Load mscoree.dll, which will also load clrjit.dll or mscorjit.dll
    LoadLibraryA("mscoree.dll");
    HMODULE hJitMod = LoadLibraryA("clrjit.dll");
    if (!hJitMod)
    {
        // very unlikely
        std::cout << "[E] Failed to load clrjit.dll" << std::endl;
        return FALSE;
    }

    PGetJit pfnGetJit = (PGetJit)GetProcAddress(hJitMod, "getJit");
    if (!pfnGetJit)
    {
        // very unlikely
        std::cout << "[E] Failed to resolve getJit()" << std::endl;
        return FALSE;
    }

    JIT* pJit = pfnGetJit();
    if (!pJit)
    {
        std::cout << "[E] getJit() returns NULL" << std::endl;
        return FALSE;
    }

    PCompileMethod pfnCompileMethod = pJit->vtbl.compileMethod;
    PLH::ErrorLog::singleton().setLogLevel(PLH::ErrorLevel::WARN);
    gHook.reset(new PLH::GDetour(
        (char *)(*((DWORD *)pfnCompileMethod)),
        (char *)&MyCompileMethod,
        &origCompileMethod,
        gDis));

    gbHooked = gHook->hook();
    if (!gbHooked)
    {
        while (true)
        {
            auto msg = PLH::ErrorLog::singleton().pop();
            if (msg.msg.length() == 0)
                break;

            std::cout << msg.msg << std::endl;
        }
        return FALSE;
    }
    return TRUE;
}


/**
 * Fini() must be called at the end right before exiting/unloading. 
 */
extern "C" __declspec(dllexport) BOOL Fini()
{
    EnterCriticalSection(&gCS);
    BOOL bRet = WriteMethodsAndHeaders();
    gLog.close();
    LeaveCriticalSection(&gCS);
    return bRet;
}


BOOL __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    InitializeCriticalSection(&gCS);
    return true;
}


