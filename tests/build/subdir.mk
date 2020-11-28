OBJECTS += ./tests.o 

CC_DEPS += ./deps/tests.d 

./%.o: ../%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -I../../include $< -o $@
	@echo 'Build finished: $<'
	@echo

