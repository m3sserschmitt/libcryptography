CC :=g++
LD :=ld
TARGET :=libcryptography.so.5.0.1
OUT :=./libcryptography.so.5.0.1
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
	$(LD) $(OBJECTS) $(LIBS) -shared -soname libcryptography.so.5 -o $(OUT)
	@echo Target $(TARGET) build successfully.
	@echo Done.

clean:
	$(RM) $(OBJECTS) ./libcryptography.so.5.0.1

static:
	ar -rvs libcryptography.a $(OBJECTS)

