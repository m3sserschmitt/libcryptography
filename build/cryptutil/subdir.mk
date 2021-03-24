OBJECTS += ./cryptutil/cryptex.o \
./cryptutil/main.o 

CC_DEPS += ./cryptutil/deps/cryptex.d \
./cryptutil/deps/main.d 

./cryptutil/%.o: ../cryptutil/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -O0 -g -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

