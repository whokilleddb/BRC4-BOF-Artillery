make:
	mkdir -p out64
	x86_64-w64-mingw32-gcc pool_injection_variants.c -DVARIANT_4 -c -o out64/variant_4_io_64.o
	x86_64-w64-mingw32-gcc pool_injection_variants.c -DVARIANT_5 -c -o out64/variant_5_alpc_64.o
	x86_64-w64-mingw32-gcc pool_injection_variants.c -DVARIANT_6 -c -o out64/variant_6_job_64.o
	x86_64-w64-mingw32-gcc pool_injection_variants.c -DVARIANT_7 -c -o out64/variant_7_direct_64.o
	x86_64-w64-mingw32-gcc pool_injection_variants.c -DVARIANT_8 -c -o out64/variant_8_timer_64.o

clean:
	rm -rf out64