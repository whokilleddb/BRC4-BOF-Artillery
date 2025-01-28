make:
	mkdir -p out64
	x86_64-w64-mingw32-gcc variant_writeio.c -c -o out64/variant_writeio_64.o
	x86_64-w64-mingw32-gcc variant_alpcportio.c -c -o out64/variant_alpcportio_64.o

clean:
	rm -rf out64