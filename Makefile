CC=g++
TARGET=libcryptography.so.4.0.1
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: libcryptography.so.4.0.1

-include $(CC_DEPS)
-include ./src/subdir.mk
-include ./src/v1/subdir.mk
-include ./src/v2/subdir.mk
-include ./src/v3/subdir.mk
-include ./src/v4/subdir.mk

libcryptography.so.4.0.1: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto -shared -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

