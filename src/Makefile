GCC=g++-10
GCC_FLAGS=-std=c++20 -g
all: build finder

finder: finder.cpp
	$(GCC) $(GCC_FLAGS) finder.cpp -o build/finder

build:
	mkdir build

clean:
	rm build/*
