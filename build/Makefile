CC :=g++
LD :=ld
TARGET :=libcryptography.so.5.0.0
OUT :=./libcryptography.so.5.0.0
LIBS :=-lcrypto
CC_DEPS :=
OBJECTS :=
RM :=rm -v

all: $(OUT)

-include ./src/subdir.mk
-include $(CC_DEPS)

$(OUT): $(OBJECTS)
	@echo Building target: "$@".
	@echo Invoking $(LD) Linker ...
	$(LD) $(OBJECTS) $(LIBS) -soname libcryptography.so.5 -shared -o $(OUT)
	@echo Target $(TARGET) build successfully.
	@echo Done.

clean:
	$(RM) $(OBJECTS) ./libcryptography.so.5.0.0

test:
	cd ../tests && make && ./tests

static:
	ar -rvs libcryptography.a $(OBJECTS)

install:
	mkdir -p -v /usr/local/include/libcryptography
	cp -r ../include/* /usr/local/include/libcryptography
	cp -v $(OUT) /usr/local/lib
	ln -v -s -f /usr/local/lib/$(TARGET) /usr/local/lib/libcryptography.so.5 
	ln -v -s -f /usr/local/lib/libcryptography.so.5 /usr/local/lib/libcryptography.so
	ldconfig /usr/local/lib
	@echo [+] Headers installed at /usr/local/include/libcryptography
	@echo [+] Library installed at /usr/local/lib/$(TARGET)
	@echo Done.

