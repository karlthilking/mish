CC = gcc
CFLAGS = -g3 -O0

define build_debug
	$(eval CFLAGS := -g3 -O0)
	$(CC) $(CFLAGS) -o shell shell.c
	echo "${CC} ${CFLAGS} -o shell shell.c"
endef

define build_release
	$(eval CFLAGS := -O3)
	$(CC) $(CFLAGS) -o shell shell.c
	echo "${CC} ${CFLAGS} -o shell shell.c"
endef

debug: 
	@$(call build_debug)

release:
	@$(call build_release)

check:
	@$(call build_release)
	./shell

clean:
	rm -f shell
