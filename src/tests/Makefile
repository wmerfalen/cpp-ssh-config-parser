GCC=g++-10
GCC_FLAGS=-std=c++20 -g
all: build main

main: main.cpp
	$(GCC) $(GCC_FLAGS) main.cpp -o build/main

build:
	mkdir build

clean:
	rm build/*
