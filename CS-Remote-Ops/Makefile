make:
	mkdir -p out64 out86
	x86_64-w64-mingw32-gcc adduser.c -c -o out64/adduser64.o
	i686-w64-mingw32-gcc adduser.c -c -o out86/adduser86.o

	x86_64-w64-mingw32-gcc make_token_cert.c -c -o out64/make_token_cert64.o
	i686-w64-mingw32-gcc make_token_cert.c -c -o out86/make_token_cert86.o

clean:
	rm -rf out64 out86