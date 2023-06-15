CC=gcc
CFLAGS=-Wall-Wextra -std=c99
build:
	 gcc Tema1.c -o vma
run_vma:
	 ./vma
clean:
	rm -f vma
