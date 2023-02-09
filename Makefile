
CC = gcc
CFLAGS = -pipe -g -Wall

RM = rm -f

## For Solaris
#LIBS += -lsocket -lnsl -lresolv

### Firewall code selection ###

## For the script based system.
#FW_OBJS=fw_program.o
#CFLAGS += -DFW_PROGRAM=\"/your/fw/program\"

## For the touch a file based system.
FW_OBJS=fw_touch.o
CFLAGS += -DFW_DIRECTORY=\"/var/spool/ipscromp\"

## For the built-in Linux method.
## Note that this only works with 2.2 kernels.
## Porting to 2.4 should be easy but I havn't done it :)
#FW_OBJS=fw_linux.o


### Digest code selection ###

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LDFLAGS += "-L/opt/homebrew/opt/openssl/lib/"
	CFLAGS += "-I/opt/homebrew/opt/openssl/include/"
endif

# For libcrpyto/OpenSSL
LIBS += -lcrypto 

# For libmd (http://www.penguin.cz/~mhi/libmd/)
#LIBS += =-lmd
#CFLAGS += -DUSE_MD

TARGETS = in.ipscrompd ipscromp fw_test ipscromp_gatekeeper

all: $(TARGETS)

install: all
	install -m 755 -s ipscromp /usr/local/bin
	install -m 755 -s in.ipscrompd /usr/local/sbin
	install -m 755 -s ipscromp_gatekeeper /usr/local/sbin
	install -m 755 scripts/ipscromp_dynfw /usr/local/sbin

ipscromp: ipscromp.o common.o
	$(CC) $(CFLAGS) -o ipscromp ipscromp.o common.o $(LDFLAGS) $(LIBS) 

in.ipscrompd: $(FW_OBJS) in.ipscrompd.o common.o auth_proto_v2.o
	$(CC) $(CFLAGS) -o in.ipscrompd in.ipscrompd.o common.o \
				auth_proto_v2.o $(FW_OBJS) $(LDFLAGS) $(LIBS)

fw_test: $(FW_OBJS) common.o fw_test.o
	$(CC) $(CFLAGS) -o fw_test $(FW_OBJS) common.o fw_test.o $(LIBS)

ipscromp_gatekeeper: ipscromp_gatekeeper.o
	$(CC) $(CFLAGS) -o ipscromp_gatekeeper ipscromp_gatekeeper.c $(LIBS)


clean:;
	$(RM) *.o core *.core *~ $(TARGETS)
