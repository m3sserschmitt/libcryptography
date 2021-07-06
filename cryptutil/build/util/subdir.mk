OBJECTS += ./util/cmd.o \
./util/log.o \
./util/util.o 

CC_DEPS += ./util/deps/cmd.d \
./util/deps/log.d \
./util/deps/util.d 

./util/%.o: ../util/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -I../../include $< -o $@
	@echo 'Build finished: $<'
	@echo

