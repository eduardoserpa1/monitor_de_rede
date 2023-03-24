CFLAGS := -O2 -Wall -fsanitize=address,undefined

main: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) main

run: main
	sudo ./main

.PHONY: clean run