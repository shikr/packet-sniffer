CC := gcc
LD := gcc

SRC_DIR := src
BUILD_DIR := build

GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_LDFLAGS := $(shell pkg-config --libs gtk+-3.0)

CFLAGS := -Wall -Wextra -O2 -I./include $(GTK_CFLAGS)
LDFLAGS := -lpcap -lpthread $(GTK_LDFLAGS)

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET := $(BUILD_DIR)/packet-sniffer

.PHONY: all
all: $(BUILD_DIR) $(TARGET) compile_commands

$(TARGET): $(OBJS)
	$(LD) $^ -o $@ $(LDFLAGS)
	@echo "[LD]  $@"

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC]  $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@

compile_commands:
	@printf '[\n' > compile_commands.json
	@first=1; for f in $(SRCS); do \
	    [ $$first -eq 0 ] && printf ',\n' >> compile_commands.json; \
	    printf '  {"directory": "%s", "command": "$(CC) $(CFLAGS) -c %s", "file": "%s"}' \
	        "$$(pwd)" "$$f" "$$f" >> compile_commands.json; \
	    first=0; \
	done
	@printf '\n]\n' >> compile_commands.json

.PHONY: run
run: all
	@./$(TARGET)

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR) compile_commands.json
	@echo "Cleaned build artifacts."
