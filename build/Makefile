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

