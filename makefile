CFLAGS := -O2 -g -Wall -fsanitize=address,undefined

main: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) main

run: main
	sudo ./main

.PHONY: clean run