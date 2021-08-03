CC :=g++
LD :=ld
TARGET :=libcryptography.so.6.0.0
OUT :=./libcryptography.so.6.0.0
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
	$(LD) $(OBJECTS) $(LIBS) -shared -soname libcryptography.so.6 -o $(OUT)
	@echo Target $(TARGET) build successfully.
	@echo Done.

clean:
	$(RM) $(OBJECTS) ./libcryptography.so.6.0.0

static:
	ar -rvs libcryptography.a ./src/*.o

