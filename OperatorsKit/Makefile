make:
	mkdir -p out64 out86
	x86_64-w64-mingw32-gcc AllowFirewallRule.c -c -o out64/AllowFirewallRule64.o
	x86_64-w64-mingw32-gcc EnumFiles.c -c -o out64/EnumFiles64.o

	i686-w64-mingw32-gcc AllowFirewallRule.c -c -o out86/AllowFirewallRule86.o
	i686-w64-mingw32-gcc EnumFiles.c -c -o out86/EnumFiles86.o

clean:
	rm -rf out64