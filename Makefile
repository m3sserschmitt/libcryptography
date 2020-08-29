CC=g++
TARGET=cryptography.so
CC_DEPS :=
OBJECTS :=
RM=rm -v

all: cryptography.so

-include ./src/subdir.mk
-include $(CC_DEPS)

cryptography.so: $(OBJECTS)
	$(CC) $(OBJECTS) -Wall -fPIC -shared -lcrypto -o $(TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET)