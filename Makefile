CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lws2_32 -liphlpapi -lpsapi
TARGET = xillen_anti_stealer.exe
SOURCE = anti_stealer.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	del $(TARGET)

.PHONY: clean
