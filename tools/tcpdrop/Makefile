src = $(wildcard *.c)
obj = $(src:.c=.o)

CC?=        cc
CFLAGS+=    -c -g -D_GNU_SOURCE -Wall -Werror
LDFLAGS =   -lbfd -lreadline -lnl-3 -lnl-genl-3

.PHONY: all clean

all: tcpdrop

tcpdrop: $(obj)
	@$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@rm -f $(obj) tcpdrop
