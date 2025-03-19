#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../badger_exports.h"

#define MAX_PREVIEW_LENGTH 200

DECLSPEC_IMPORT char* WINAPI Msvcrt$strstr(const char* haystack, const char* needle);
DECLSPEC_IMPORT int WINAPI Msvcrt$_strnicmp(char *string1, char *string2, size_t count);
DECLSPEC_IMPORT char* WINAPI Msvcrt$_strdup(const char* str);
DECLSPEC_IMPORT void WINAPI Msvcrt$free(void *memblock);
DECLSPEC_IMPORT int WINAPI Msvcrt$tolower(int c);
DECLSPEC_IMPORT char* WINAPI Msvcrt$strtok(char* str, const char* delimiters);
DECLSPEC_IMPORT char* WINAPI Msvcrt$strcat(char* dest, const char* src);
DECLSPEC_IMPORT int WINAPI Msvcrt$sprintf(char* buffer, const char* format, ...);
DECLSPEC_IMPORT char* WINAPI Msvcrt$strcpy(char *strDestination, const char *strSource);
DECLSPEC_IMPORT char* WINAPI Msvcrt$strncpy(char* dest, const char* src, size_t n);
DECLSPEC_IMPORT int WINAPI MSVCRT$strncmp(const char* str1, const char* str2, size_t n);

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT BOOL WINAPI Kernel32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT DWORD WINAPI Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetFileSize(HANDLE  hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD  nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);


bool keywordMatches(char* content, char* keyword) {
    size_t keywordLen = BadgerStrlen(keyword);
    size_t contentLen = BadgerStrlen(content);
    size_t subtr;

    if (keyword[0] == '*' && keyword[keywordLen - 1] == '*') {
        char tempKeyword[MAX_PATH]= {0};
        Msvcrt$strncpy(tempKeyword, keyword + 1, keywordLen - 2);
        tempKeyword[keywordLen - 2] = '\0';
        if (Msvcrt$strstr(content, tempKeyword)) {
            return true;
        }
    } else if (keyword[keywordLen - 1] == '*') {
        char tempKeyword[MAX_PATH]= {0};
        Msvcrt$strncpy(tempKeyword, keyword, keywordLen - 1);
        tempKeyword[keywordLen - 1] = '\0';
        if (MSVCRT$strncmp(content, tempKeyword, keywordLen - 1) == 0) {
            return true;
        }
    } else if (keyword[0] == '*') {
        subtr = BadgerStrlen(content) - (keywordLen - 1) - 1;
        if (BadgerStrlen(content) >= keywordLen - 1) {
            if (Msvcrt$_strnicmp(content + subtr, keyword + 1, keywordLen-1) == 0) {
                return true;
            } else if (BadgerStrcmp(content + subtr + 1, keyword + 1) == 0) {
                return true;
            }
        }
    } else if (Msvcrt$strstr(content, keyword)) {
        return true;
    }
    return false;
}

bool SearchFileForKeyword(char* filePath, char* keyword) {
    DWORD dwBytesRead = 0;
    DWORD fileSize = 0;
    HANDLE hFile;
    
    hFile = Kernel32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) {
        BadgerDispatch(g_dispatch, "[-] CreateFileA failed to open file: %s with error %lu\n", filePath, Kernel32$GetLastError());
        return false;
    }
    fileSize = Kernel32$GetFileSize(hFile, NULL);
    if (!fileSize) {
        BadgerDispatch(g_dispatch, "[-] Failed to get file size: %s with error %lu\n", filePath, Kernel32$GetLastError());
        Kernel32$CloseHandle(hFile);
        return false;
    }
    char* fileContents = (char*)BadgerAlloc(fileSize + 1);

    if (!fileContents) {
        BadgerDispatch(g_dispatch, "[-] Failed to allocate memory for file: %s with error %lu\n", filePath, Kernel32$GetLastError());
        return false;
    }
    if (!Kernel32$ReadFile(hFile, fileContents, fileSize, &dwBytesRead, NULL)) {
        BadgerDispatch(g_dispatch, "[-] ReadFile failed: %lu\n", Kernel32$GetLastError());
        BadgerFree((PVOID*)&fileContents);
        if(!Kernel32$CloseHandle(hFile)) {
            BadgerDispatch(g_dispatch, "[-] Failed to close the file handle %lu\n", Kernel32$GetLastError());
        }
        return false;
    }
    fileContents[dwBytesRead] = '\0';  
    Kernel32$CloseHandle(hFile);
    for (long i = 0; i < dwBytesRead; i++) {
        fileContents[i] = Msvcrt$tolower(fileContents[i]);
    }
    char* lowerKeyword = Msvcrt$_strdup(keyword);
    if (!lowerKeyword) {
        BadgerFree((PVOID*)&fileContents);
        BadgerDispatch(g_dispatch, "[-] Converting keyword to lowercase failed %lu\n", Kernel32$GetLastError());
        return false;
    }
    for (int i = 0; lowerKeyword[i]; i++) {
        lowerKeyword[i] = Msvcrt$tolower(lowerKeyword[i]);
    }
    char* line = Msvcrt$strtok(fileContents, "\n");
    bool found = false;
	bool firstPrint = true;
    char preview[MAX_PREVIEW_LENGTH + 1]; 
    while (line) {
        if (keywordMatches(line, lowerKeyword)) {
            found = true;
            int lineLength = BadgerStrlen(line);
            if (lineLength > MAX_PREVIEW_LENGTH) {
                Msvcrt$strncpy(preview, line, MAX_PREVIEW_LENGTH);
                preview[MAX_PREVIEW_LENGTH] = '\0'; 
            } else {
                BadgerMemcpy(preview, line, BadgerStrlen(line)+1);
            }
            if (firstPrint) {
                BadgerDispatch(g_dispatch, "[+] Keyword '%s' found in file: %s\n", keyword, filePath);
                firstPrint = false;
            }
            BadgerDispatch(g_dispatch, "  - Matched on pattern: %s\n", preview);
        }
        line = Msvcrt$strtok(NULL, "\n");
    }
    BadgerFree((PVOID*)&fileContents);
    Msvcrt$free(lowerKeyword);
    return found;
}

BOOL SearchFilesRecursive(char* lpFolder, char* lpSearchPattern, char* keyword) {
    BOOL found = FALSE;
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char szDir[MAX_PATH] = { 0 };
    char subDir[MAX_PATH] = { 0 };
    DWORD dwError;

    BadgerMemcpy(szDir, lpFolder, BadgerStrlen(lpFolder)+1);
    if (szDir[BadgerStrlen(szDir)-1] != '\\') {
        Msvcrt$strcat(szDir, "\\");
    }
    Msvcrt$strcat(szDir, lpSearchPattern);
    hFind = Kernel32$FindFirstFileA(szDir, &findFileData);
    if (!hFind) {
        BadgerDispatch(g_dispatch, "FindFirstFileA Error %lu\n", Kernel32$GetLastError());
        return FALSE;
    }
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char fullPath[MAX_PATH] = { 0 };
                if (lpFolder[BadgerStrlen(lpFolder)-1] != '\\') {
                    Msvcrt$sprintf(fullPath, "%s\\%s", lpFolder, findFileData.cFileName);
                } else {
                    Msvcrt$sprintf(fullPath, "%s%s", lpFolder, findFileData.cFileName);
                }
                if (*keyword) {
                    BOOL currentFind = SearchFileForKeyword(fullPath, keyword);
                    if (! found) {
                        found = currentFind;
                    }
                } else if (!*keyword) {
                    BadgerDispatch(g_dispatch, "[+] File found: %s\n", fullPath);
                }
            }
        } while (Kernel32$FindNextFileA(hFind, &findFileData) != 0);
        dwError = Kernel32$GetLastError();
        if (dwError != ERROR_NO_MORE_FILES) {
            BadgerDispatch(g_dispatch, "[-] Error searching next file: %d\n", dwError);
        }
        Kernel32$FindClose(hFind);
    }

    BadgerMemset(szDir, 0, MAX_PATH);
    BadgerMemcpy(szDir, lpFolder, BadgerStrlen(lpFolder)+1);
    Msvcrt$strcat(szDir, "\\*");
    hFind = Kernel32$FindFirstFileA(szDir, &findFileData);
    if (!hFind) {
        BadgerDispatch(g_dispatch, "FindFirstFileA Error %lu\n", Kernel32$GetLastError());
        return FALSE;
    }
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                BadgerStrcmp(findFileData.cFileName, ".") != 0 && 
                BadgerStrcmp(findFileData.cFileName, "..") != 0) {
                BadgerMemset(subDir, 0, MAX_PATH);
                BadgerMemcpy(subDir, lpFolder, BadgerStrlen(lpFolder)+1);
                if (subDir[BadgerStrlen(subDir)-1] != '\\') {
                    Msvcrt$strcat(subDir, "\\");
                }
                Msvcrt$strcat(subDir, findFileData.cFileName);
                SearchFilesRecursive(subDir, lpSearchPattern, keyword);
            }
        } while (Kernel32$FindNextFileA(hFind, &findFileData) != 0);
        dwError = Kernel32$GetLastError();
        if (dwError != ERROR_NO_MORE_FILES) {
            BadgerDispatch(g_dispatch, "[-] Error searching for next file: %d\n", dwError);
        }
        Kernel32$FindClose(hFind);
    }
    return found;
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    char *lpDirectory = NULL;
    char *lpSearchPattern = NULL;
    char *keyword = NULL;
    g_dispatch = dispatch;
    if (argc < 2) {
        BadgerDispatch(dispatch, "[!] Usage: EnumFiles.o <path to directory> <search pattern> <(optional)keyword>\nExamples: \n1. EnumFiles.o C:\\Users\\RTO\\Documents *.xlsx \n2. EnumFiles.o C:\\Users\\RTO *login*.* username\n3. EnumFiles.o C:\\Users\\RTO *.txt *pass*\n");
        return;
    }
    lpDirectory = argv[0];
    lpSearchPattern = argv[1];
    BadgerDispatch(dispatch, "[*] Directory: %s\n", lpDirectory);
    BadgerDispatch(dispatch, "[*] SearchPattern: %s\n", lpSearchPattern);
    if (argc == 3) {
        keyword = argv[2];
        BadgerDispatch(dispatch, "[*] keyword: %s\n", keyword);
    }
    BadgerDispatch(dispatch, "[+] Search Results:\n");
    if (SearchFilesRecursive(lpDirectory, lpSearchPattern, keyword)) {
        BadgerDispatch(dispatch, "[+] Success\n");
        return;
    }
    BadgerDispatch(dispatch, "[-] No results found\n");
    return;
}