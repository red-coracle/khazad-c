TARGET = testvectors
CFLAGS = -O3 -march=native

$(TARGET): bctestvectors.o libkhazad.a
	gcc $(CFLAGS)  $^ -o $@

bctestvectors.o: bctestvectors.c
	gcc $(CFLAGS) -c $< -o $@

libkhazad.a: libkhazad1.o
	ar rcs $@ $^

libkhazad1.o: khazad-tweak.c nessie.h
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.a $(TARGET)
