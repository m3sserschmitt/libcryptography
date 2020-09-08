CC=g++
TARGET=libcryptography.so
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: libcryptography.so

-include ./src/subdir.mk
-include $(CC_DEPS)

libcryptography.so: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto -fPIC -Wall -shared -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

