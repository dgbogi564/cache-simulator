SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

EXE := $(BIN_DIR)/cache-simulator
SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)


CPPFLAGS := -MMD -MP -ggdb
CFLAGS	 :=  -Wall -Werror -std=c11 #TODO add back -fsanitize=address
LDFLAGS	 :=  -Llib #TODO add back -fsanitize=address
LDLIBS	 := -lm

.PHONY: all env debug clean

all: $(EXE)

debug: export CACHE_DEBUG = 1
debug: export LSAN_OPTIONS=verbosity=1:log_threads=1
debug: $(EXE)
	@echo CACHE_DEBUG = $$CACHE_DEBUG

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	$(RM) -rv $(EXE) $(BIN_DIR) $(OBJ_DIR)

#-include $(OBJ:.o=.d)