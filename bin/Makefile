all: example static

example: example.c
	gcc -o example example.c
	strip -s --strip-unneeded --strip-section-headers example

static: static.c
	gcc -nostdlib -lc -static -fPIE -fno-stack-protector -pie -o static static.c
	strip -s --strip-unneeded --strip-section-headers static

.PHONY: clean
clean:
	rm -f example static

