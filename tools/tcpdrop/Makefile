src = $(wildcard *.c)
obj = $(src:.c=.o)

CC?=        cc
CFLAGS+=    -c -g -D_GNU_SOURCE -Wall -Werror
LDFLAGS =   -lnl-3 -lnl-genl-3
C_INCLUDE_PATH += -I/usr/include/libnl3/

.PHONY: all clean

all: tcpdrop

tcpdrop: $(obj)
	@$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@$(CC) $(C_INCLUDE_PATH) $(CFLAGS) -o $@ -c $<

clean:
	@rm -f $(obj) tcpdrop
