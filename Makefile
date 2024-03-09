CC=gcc
CFLAGS=

fuzzer: clean fuzz.c
	$(CC) $(CFLAGS) -o fuzzer fuzz.c
	
run : fuzzer
	./fuzzer ./extractor_x86_64

clean:
	rm -f fuzzer fuzz *.tar *.txt