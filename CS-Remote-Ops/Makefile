make:
	mkdir -p out64 out86
	x86_64-w64-mingw32-gcc adduser.c -c -o out64/adduser64.o
	i686-w64-mingw32-gcc adduser.c -c -o out86/adduser86.o

	x86_64-w64-mingw32-gcc make_token_cert.c -c -o out64/make_token_cert64.o
	i686-w64-mingw32-gcc make_token_cert.c -c -o out86/make_token_cert86.o

	x86_64-w64-mingw32-gcc reg_set.c -c -o out64/reg_set64.o
	i686-w64-mingw32-gcc reg_set.c -c -o out86/reg_set86.o

	x86_64-w64-mingw32-gcc change_pass.c -c -o out64/change_pass64.o
	i686-w64-mingw32-gcc change_pass.c -c -o out86/change_pass86.o

	x86_64-w64-mingw32-gcc adcs_request/adcs_request.c -c -o out64/adcs_request64.o
	i686-w64-mingw32-gcc adcs_request/adcs_request.c -c -o out86/adcs_request86.o

	x86_64-w64-mingw32-gcc adcs_enum/adcs_enum.c -c -o out64/adcs_enum64.o
	i686-w64-mingw32-gcc adcs_enum/adcs_enum.c -c -o out86/adcs_enum86.o

	x86_64-w64-mingw32-gcc reg_save.c -c -o out64/reg_save64.o
	i686-w64-mingw32-gcc reg_save.c -c -o out86/reg_save86.o

	x86_64-w64-mingw32-gcc shutdown.c -c -o out64/shutdown64.o
	i686-w64-mingw32-gcc shutdown.c -c -o out86/shutdown86.o

	x86_64-w64-mingw32-gcc reg_del.c -c -o out64/reg_del64.o
	i686-w64-mingw32-gcc reg_del.c -c -o out86/reg_del86.o

	x86_64-w64-mingw32-gcc unexpire_user.c -c -o out64/unexpire_user64.o
	i686-w64-mingw32-gcc unexpire_user.c -c -o out86/unexpire_user86.o

	x86_64-w64-mingw32-gcc schtasks/schtasks_create.c -c -o out64/schtasks_create64.o
	i686-w64-mingw32-gcc schtasks/schtasks_create.c -c -o out86/schtasks_create86.o

clean:
	rm -rf out64 out86