example: example.c
	gcc -o example example.c

static: static.c
	gcc -nostdlib -lc -static -fPIE -fno-stack-protector -pie -o static static.c
