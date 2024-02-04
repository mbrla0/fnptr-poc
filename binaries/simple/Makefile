AS=x86_64-unknown-linux-gnu-as
LD=x86_64-unknown-linux-gnu-ld

OBJS=main.o

simple: $(OBJS) link.ld
	$(LD) -o $@ -T link.ld $(OBJS)

.s.o:
	$(AS) -o $@ $<

clean:
	rm -rf simple *.o
.PHONY: clean
