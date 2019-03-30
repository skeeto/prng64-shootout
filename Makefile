.POSIX:
.SUFFIXES:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3 -g3 -march=native

results = \
    xorshift64star.txt \
    xorshift128plus.txt \
    xorshift1024star.txt \
    xoroshiro128plus.txt \
    blowfishcbc16.txt \
    blowfishcbc4.txt \
    blowfishctr16.txt \
    blowfishctr4.txt \
    mt64.txt \
    pcg128.txt \
    rc4.txt

shootout: shootout.c blowfish.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ shootout.c blowfish.c $(LDLIBS)

test: check
check: shootout $(results)

xorshift64star.txt: shootout
	./shootout -g1  | dieharder -g200 -a -m4 | tee $@
xorshift128plus.txt: shootout
	./shootout -g2  | dieharder -g200 -a -m4 | tee $@
xorshift1024star.txt: shootout
	./shootout -g3  | dieharder -g200 -a -m4 | tee $@
xoroshiro128plus.txt: shootout
	./shootout -g4  | dieharder -g200 -a -m4 | tee $@
blowfishcbc16.txt: shootout
	./shootout -g5  | dieharder -g200 -a -m4 | tee $@
blowfishcbc4.txt: shootout
	./shootout -g6  | dieharder -g200 -a -m4 | tee $@
blowfishctr16.txt: shootout
	./shootout -g7  | dieharder -g200 -a -m4 | tee $@
blowfishctr4.txt: shootout
	./shootout -g8  | dieharder -g200 -a -m4 | tee $@
mt64.txt: shootout
	./shootout -g9  | dieharder -g200 -a -m4 | tee $@
spcg64.txt: shootout
	./shootout -g10 | dieharder -g200 -a -m4 | tee $@
pcg64.txt: shootout
	./shootout -g11 | dieharder -g200 -a -m4 | tee $@
rc4.txt: shootout
	./shootout -g12 | dieharder -g200 -a -m4 | tee $@
msws64.txt: shootout
	./shootout -g13 | dieharder -g200 -a -m4 | tee $@
xoshiro256starstar.txt: shootout
	./shootout -g14 | dieharder -g200 -a -m4 | tee $@
splitmix64.txt: shootout
	./shootout -g15 | dieharder -g200 -a -m4 | tee $@
bjsmall64.txt: shootout
	./shootout -g16 | dieharder -g200 -a -m4 | tee $@

clean:
	rm -f shootout $(results)
