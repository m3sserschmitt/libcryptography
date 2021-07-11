CC :=g++
LD :=g++
TARGET :=tests
OUT :=./tests
LIBS :=-lcryptography
CC_DEPS :=
OBJECTS :=
RM :=rm -v

all: $(OUT)

-include ./subdir.mk
-include $(CC_DEPS)

$(OUT): $(OBJECTS)
	@echo Building target: "$@".
	@echo Invoking $(LD) Linker ...
	$(LD) $(OBJECTS) $(LIBS)  -o $(OUT)
	@echo Target $(TARGET) build successfully.
	@echo Done.

clean:
	$(RM) $(OBJECTS) ./tests

