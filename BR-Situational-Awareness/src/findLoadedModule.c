#include "common.h"

void usage() {
    PRINT("[+] Usage:\n");
    PRINT("      findLoadedModule [modulepart] [opt:procnamepart]\n\n");
    PRINT("[+] Description:\n");
    PRINT("      Find what processes *modulepart* are loaded into, optionally searching just *procnamepart*");
}


void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;

    // Check for help flag
    if (argc == 1) {
      if (
            (BadgerStrcmp(argv[0], "-h") == 0) ||
            (BadgerStrcmp(argv[0], "--help") == 0) ||
            (BadgerStrcmp(argv[0], "/?") == 0)
        ) {
        usage();
        return;
        }
    }

    if (argc > 2) {
        usage();
        return;
    }

    char * modSearchString = NULL;
    char * procSearchString = NULL;

}