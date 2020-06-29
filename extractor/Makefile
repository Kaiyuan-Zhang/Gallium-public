CC := gcc
CXX := g++
MAKE := make
AR := ar
LD := LD

LLVM_CONFIG := llvm-config

LLVM_INCDIR := $(shell "$(LLVM_CONFIG)" --includedir)
LLVM_LIBDIR := $(shell "$(LLVM_CONFIG)" --libdir)
LLVM_LIBS := $(shell "$(LLVM_CONFIG)" --libs)
LLVM_SYSLIBS := $(shell "$(LLVM_CONFIG)" --system-libs)

DOT := dot

SRC_DIR := src
EXEC_DIR := exec
BIN_DIR := bin
OBJ_DIR := obj
INC_DIR := include

VIZ_DIR := figs

INC_FLAGS := -I$(INC_DIR) -I$(LLVM_INCDIR)

HEADERS := $(wildcard include/*.hpp)
HEADERS += $(wildcard include/*.h)

CXXFLAGS = -std=c++1z -O3 $(INC_FLAGS) -MMD

LIB_NAME := libextractor.a
SO_LIB_NAME := libextractor.so

LIB_SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
LIB_OBJ_FILES := $(subst $(SRC_DIR)/,,$(LIB_SRC_FILES:%.cpp=$(OBJ_DIR)/%.o))

EXEC_FILES := $(wildcard $(EXEC_DIR)/*.cpp)
EXEC_TARGETS := $(subst $(EXEC_DIR)/,,$(EXEC_FILES:%.cpp=$(BIN_DIR)/%))

DOT_FILES := $(wildcard *.dot)
DOT_TARGETS := $(DOT_FILES:%.dot=$(VIZ_DIR)/%.pdf)

all: $(OBJ_DIR) $(BIN_DIR) $(LIB_NAME) $(SO_LIB_NAME) $(EXEC_TARGETS)

debug: CXXFLAGS := -std=c++1z -O0 -g $(INC_FLAGS) -MMD
debug: all

viz: $(VIZ_DIR) $(DOT_TARGETS)

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

$(VIZ_DIR):
	@mkdir -p $@

$(LIB_NAME): $(LIB_OBJ_FILES)
	$(AR) cr $@ $^

$(SO_LIB_NAME): $(LIB_OBJ_FILES)
	@echo "TODO: make so file"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) -fPIC $(CXXFLAGS) -c -o $@ $< $(LDFLAGS)

$(BIN_DIR)/%: $(EXEC_DIR)/%.cpp $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_NAME) $(LDFLAGS) -L$(LLVM_LIBDIR) $(LLVM_LIBS) $(LLVM_SYSLIBS)

$(VIZ_DIR)/%.pdf: %.dot
	dot -Tpdf $< -o $@


.PHONY: clean debug all viz
clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR) $(LIB_NAME) $(SO_LIB_NAME) $(VIZ_DIR)
	rm -rf *.dot
