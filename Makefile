CC=g++
TARGET=libcryptography.so.0.0.1
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: libcryptography.so.0.0.1

-include ./src/subdir.mk
-include $(CC_DEPS)

libcryptography.so.0.0.1: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto -shared -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

