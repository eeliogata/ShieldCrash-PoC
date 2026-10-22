TOOLCHAIN := x86_64-w64-mingw32
CXX := $(TOOLCHAIN)-g++
WINDRES := $(TOOLCHAIN)-windres

BUILD := build
TARGET := $(BUILD)/ShieldCrash.exe
CPPFLAGS := -DUNICODE -D_UNICODE
CXXFLAGS := -std=c++20 -O2
LDFLAGS := -municode -static
LDLIBS := -lntdll -ladvapi32 -lole32

.PHONY: all clean
all: $(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/ShieldCrash.o: ShieldCrash.cpp resource.h | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BUILD)/ShieldCrash.res.o: ShieldCrash.rc resource.h eicar_com.zip | $(BUILD)
	$(WINDRES) -I . -i $< -o $@

$(TARGET): $(BUILD)/ShieldCrash.o $(BUILD)/ShieldCrash.res.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD)
