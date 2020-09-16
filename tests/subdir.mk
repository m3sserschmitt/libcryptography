OBJECTS += ./tests.o

CC_DEPS += ./deps/tests.d

./%.o: ./%.cc
	$(CC) -Wall -c $< -o $@

