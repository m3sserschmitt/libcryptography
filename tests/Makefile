CC=g++
TARGET=tests
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: tests

-include $(CC_DEPS)
-include ./subdir.mk

tests: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto ../libcryptography.so.* -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

