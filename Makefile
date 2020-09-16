CC=g++
TARGET=libcryptography.so.4.0.3
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: libcryptography.so.4.0.3

-include $(CC_DEPS)
-include ./src/subdir.mk
-include ./src/v1/subdir.mk
-include ./src/v2/subdir.mk
-include ./src/v3/subdir.mk
-include ./src/v4/subdir.mk

libcryptography.so.4.0.3: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto -shared -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

test:
	cd tests && make && ./tests

clean_all:
	make clean && cd tests && make clean

