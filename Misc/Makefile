CC=x86_64-w64-mingw32-gcc
CFLAGS=-m64 -Os -s -pedantic -nostdlib -fno-jump-tables -fdiagnostics-color=always -fno-ident -Wshadow -Wconversion -Wall -c
INCLUDES=../BR-Situational-Awareness/includes
SRC=src

.PHONY: all clean

all:
	$(MAKE) TARGET=enable_efs bof

bof:
	$(CC) $(CFLAGS) -I $(INCLUDES) -o $(TARGET).o $(TARGET).c
	@mkdir -p bofs/
	@mv *.o ./bofs/

enable_efs:
	$(MAKE) TARGET=enable_efs bof

clean:
	@rm -rf ../bofs
