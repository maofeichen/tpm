CC	= gcc
CF	= -Wall -g -std=c11
LF	= -g

OBJS	= main.o tpm.o

all	: tpm

tpm	: $(OBJS)
	$(CC) $(LF) -o tpm $(OBJS) 

main.o : main.c
	$(CC) $(CF)	-c main.c 

tpm.o : tpm.c
	$(CC) $(CF) -c tpm.c

clean	:
	rm -rf *.o tpm
