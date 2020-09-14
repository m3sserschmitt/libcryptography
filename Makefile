CC=g++
TARGET=libcryptography.so.0.0.3
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: libcryptography.so.0.0.3

-include ./src/v1/subdir.mk
-include ./src/v3/subdir.mk
-include ./src/v2/subdir.mk
-include ./src/subdir.mk
-include $(CC_DEPS)

libcryptography.so.0.0.3: $(OBJECTS)
	$(CC) $(OBJECTS) -lcrypto -shared -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)

