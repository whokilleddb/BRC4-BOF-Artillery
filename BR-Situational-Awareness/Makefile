CC=x86_64-w64-mingw32-gcc
CFLAGS=-m64 -Os -s -pedantic -nostdlib -fno-jump-tables -fdiagnostics-color=always -fno-ident -Wshadow -Wconversion -Wall -c
INCLUDES=includes/
SRC=src

.PHONY: all clean 

all:
	$(MAKE) dir
	$(MAKE) enum_filter_driver

bof: 
	$(CC) $(CFLAGS) -I $(INCLUDES) -o $(TARGET).o $(SRC)/$(TARGET).c
	@mkdir -p bofs/
	@mv *.o ./bofs/

enum_filter_driver:
	$(MAKE) TARGET=enum_filter_driver bof

dir:
	$(MAKE) TARGET=dir bof

clean:
	@rm -rf ../bofs 
