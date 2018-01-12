CC	= gcc
# CF	= -Wall -g -std=c11 -DDEBUG 
# LF	= -g -DDEBUG 
CF	= -Wall -g -std=c11 
LF	= -g 

OBJS	= main.o tpm.o tpmnode.o record.o stat.o propagate.o avalanche.o continbuf.o avalanchetype.o \
		  misc.o

all	: tpm #testtpm

testtpm : testtpm.o tpm.o record.o
	$(CC) $(LF) -o testtpm testtpm.o record.o

testtpm.o : testtpm.c
	$(CC) $(CF)	-c testtpm.c 

tpm	: $(OBJS)
	$(CC) $(LF) -o tpm $(OBJS) 

main.o : main.c
	$(CC) $(CF)	-c main.c 

tpm.o : tpm.c
	$(CC) $(CF) -c tpm.c

record.o : record.c
	$(CC) $(CF) -c record.c

stat.o : stat.c
	$(CC) $(CF) -c stat.c

avalanche.o: avalanche.c
	$(CC) $(CF) -c avalanche.c

propagate.o: propagate.c
	$(CC) $(CF) -c propagate.c

tpmnode.o: tpmnode.c
	$(CC) $(CF) -c tpmnode.c

continbuf.o: continbuf.c
	$(CC) $(CF) -c continbuf.c

avalanchetype.o: avalanchetype.c
	$(CC) $(CF) -c avalanchetype.c

misc.o: misc.c
	$(CC) $(CF) -c misc.c

clean	:
	rm -rf *.o tpm testtpm
