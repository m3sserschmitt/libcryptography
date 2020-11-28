CC :=cc
LD :=ld
TARGET :=libcryptography.so.4.0.5
OUT :=./libcryptography.so.4.0.5
LIBS :=-lcrypto
CC_DEPS :=
OBJECTS :=
RM :=rm -v

all: $(OUT)

-include ./crypto/v1/subdir.mk
-include ./crypto/v2/subdir.mk
-include ./crypto/v3/subdir.mk
-include ./crypto/v4/subdir.mk
-include $(CC_DEPS)

$(OUT): $(OBJECTS)
	@echo Building target: "$@".
	@echo Invoking $(LD) Linker ...
	$(LD) $(OBJECTS) $(LIBS) -soname libcryptography.so.4 -shared -o $(OUT)
	@echo Target $(TARGET) build successfully.
	@echo Done.

clean:
	$(RM) $(OBJECTS) ./libcryptography.so.4.0.5

test:
	cd ../tests/build && make && ./tests

clean_test:
	cd ../tests/build && make clean

install:
	mkdir -p -v /usr/local/include/libcryptography
	cp -r ../include/crypto /usr/local/include/libcryptography
	cp -v $(OUT) /usr/local/lib
	ln -v -s -f /usr/local/lib/$(TARGET) /usr/local/lib/libcryptography.so.4 
	ln -v -s -f /usr/local/lib/libcryptography.so.4 /usr/local/lib/libcryptography.so
	ldconfig /usr/local/lib
	@echo [+] Headers installed at /usr/local/include/libcryptography
	@echo [+] Library installed at /usr/local/lib/$(TARGET)
	@echo Done.

