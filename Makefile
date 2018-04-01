CC	= gcc
# CF	= -Wall -g -std=c11 -DDEBUG 
# LF	= -g -DDEBUG 
CF	= -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-label -g -std=c11 
LF	= -g 

OBJS	= main.o tpm.o tpmnode.o record.o stat.o propagate.o avalanche.o continbuf.o avalanchetype.o \
		  misc.o hitmapnode.o hitmap.o hitmapavaltype.o hitmapavalanche.o hitmappropagate.o bufhitcnt.o \
		  hitmap_addr2nodeitem_datastruct.o

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

hitmapnode.o: hitmapnode.c
	$(CC) $(CF) -c hitmapnode.c

hitmap.o: hitmap.c
	$(CC) $(CF) -c hitmap.c

hitmapavaltype.o: hitmapavaltype.c
	$(CC) $(CF) -c hitmapavaltype.c

hitmapavalanche.o: hitmapavalanche.c
	$(CC) $(CF) -c hitmapavalanche.c

hitmappropagate.o: hitmappropagate.c
	$(CC) $(CF) -c hitmappropagate.c

bufhitcnt.o: bufhitcnt.c
	$(CC) $(CF) -c bufhitcnt.c

hitmap_addr2nodeitem_datastruct.o: hitmap_addr2nodeitem_datastruct.c
	$(CC) $(CF) -c hitmap_addr2nodeitem_datastruct.c

misc.o: misc.c
	$(CC) $(CF) -c misc.c

clean	:
	rm -rf *.o tpm testtpm
