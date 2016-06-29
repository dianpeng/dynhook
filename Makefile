LUA=luajit
AWK=awk
GPP=g++
GCC=gcc
FLAGS:=-O2
SRC = $(wildcard src/*.cc)
HDR = $(wildcard src/*h)
OBJ = ${SRC:.cc=.o}
DASC= $(wildcard src/*.dasc)
INSTR_SRC = $(wildcard instr/*.c)
INSTR_HDR = $(wildcard instr/*.h)
INSTR_OBJ = $(INSTR_SRC:.c=.o)
OBJ_FOLDER = bin/
LINK = -lelf -lpthread -lglog -ludis86 -lboost_system \
	-lboost_filesystem -lboost_program_options

all: bin_folder dynhook

bin_folder:
	mkdir -p $(OBJ_FOLDER)

preprocess: $(DASC)
	$(LUA) dynasm/dynasm.lua -o src/stub.pp.cc src/stub.dasc
	$(LUA) dynasm/dynasm.lua -o src/patch.pp.cc src/patch.dasc

libinstruction_inat : instr/gen-insn-attr-x86.awk instr/x86-opcode-map.txt
	LC_ALL=C $(AWK) -f $? > instr/inat-tables.c

libinstr: $(INSTR_SRC) $(INSTR_HDR) libinstruction_inat
	$(GCC) -c instr/insn.c -o $(OBJ_FOLDER)/insn.o $(FLAGS)
	$(GCC) -c instr/inat.c -o $(OBJ_FOLDER)/inat.o $(FLAGS)
	ar rcs $(OBJ_FOLDER)/libinstr.a $(OBJ_FOLDER)/insn.o $(OBJ_FOLDER)/inat.o

dynhook: libinstr $(SRC) $(HDR) preprocess
	$(GPP) $(SRC) -o $(OBJ_FOLDER)/dynhook -L./bin/ -linstr $(LINK)

program:
	$(GPP) -fPIC -O2 ./program.cc -g3 -o $(OBJ_FOLDER)/program -ldl

testso:
	$(GPP) -fPIC -shared -g3 -o $(OBJ_FOLDER)/libtestso.so -fPIC ./test-so.cc

.PHONY:clean bin_folder

clean:
	rm -rf bin/
