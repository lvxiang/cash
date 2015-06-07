main: shell.c util.o
	gcc -o shell.o shell.c util.o

util.o: util.h util.c
	gcc -c util.c

clean:
	rm util.o shell.o