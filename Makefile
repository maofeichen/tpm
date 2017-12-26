CC	= gcc
# CF	= -Wall -g -std=c11 -DDEBUG 
# LF	= -g -DDEBUG 
CF	= -Wall -g -std=c11 
LF	= -g 

OBJS	= main.o tpm.o util.o stat.o propagate.o 

all	: tpm testtpm

testtpm : testtpm.o tpm.o util.o
	$(CC) $(LF) -o testtpm testtpm.o util.o

testtpm.o : testtpm.c
	$(CC) $(CF)	-c testtpm.c 

tpm	: $(OBJS)
	$(CC) $(LF) -o tpm $(OBJS) 

main.o : main.c
	$(CC) $(CF)	-c main.c 

tpm.o : tpm.c
	$(CC) $(CF) -c tpm.c

util.o : util.c
	$(CC) $(CF) -c util.c

stat.o : stat.c
	$(CC) $(CF) -c stat.c

avalanche.o: avalanche.c
	$(CC) $(CF) -c avalanche.c

propagate.o: propagate.c
	$(CC) $(CF) -c propagate.c

clean	:
	rm -rf *.o tpm testtpm
