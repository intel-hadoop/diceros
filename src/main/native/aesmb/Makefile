EXE=test
LIB=libaesmb.so
YASM := $(YASM_BIN)
OBJ_DIR=obj
INCLUDE_DIRS := ../include .

INCLUDES := $(foreach i,$(INCLUDE_DIRS),-I $i)

CXX := g++
CC  := gcc
CXXFLAGS := -g -std=gnu99 -D DEBUG -D AESMB_TEST_MAIN -D LINUX -D NDEBUG $(INCLUDES) -fPIC 
ASMFLAGS := -f  x64 -f elf64 -X gnu -g dwarf2 -DPIC -D LINUX -D __linux__ $(INCLUDES) 
LDFLAGS += -g

obj_files := aes128_cbcenc_x8.o \
	aes192_cbcenc_x8.o \
	aes256_cbcenc_x8.o \
	aes_cbc_dec_by8_sse.o \
	aes_keyexp_128.o \
	aes_keyexp_192.o \
	aes_keyexp_256.o 


obj2_files := $(obj_files:%=$(OBJ_DIR)/%)

.PHONY: all lib clean

all: lib 

lib: $(LIB) 

exe: $(EXE)

compile: $(obj2_files)

$(LIB): $(obj2_files)
	@ echo "LIB---------------------"
	$(CC) -shared -ldl -Wl,-soname,$(LIB) -o $@ $^

a.out: $(obj2_files) $(test_files)
	@ echo "a.out----------------------"
	$(CC) $(LDFLAGS) -o $@ $^

$(obj2_files): | $(OBJ_DIR)

$(OBJ_DIR)/%.o:%.cpp
	@ echo "Making object file $@ "
	$(CXX) -c $(CXXFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CXXFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:%.asm
	@ echo "Making object file $@ "
	$(YASM) $(ASMFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR):
	@ echo "before make----------- "
	mkdir $(OBJ_DIR)

clean:
	rm -Rf $(obj2_files)
	rm -Rf $(LIB)
