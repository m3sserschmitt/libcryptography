OBJECTS += ./cryptography/tests/main.o 

CC_DEPS += ./cryptography/tests/deps/main.d 

./cryptography/tests/%.o: ./cryptography/tests/%.c
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

./cryptography/tests/%.o: ./cryptography/tests/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

./cryptography/tests/%.o: ./cryptography/tests/%.cpp
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

