OBJECTS += ./cryptutil/util/cmd.o \
./cryptutil/util/log.o \
./cryptutil/util/util.o 

CC_DEPS += ./cryptutil/util/deps/cmd.d \
./cryptutil/util/deps/log.d \
./cryptutil/util/deps/util.d 

./cryptutil/util/%.o: ../cryptutil/util/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -O0 -g -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

