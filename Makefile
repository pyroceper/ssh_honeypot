all:
	g++ src/main.cpp -I./include/ -lssh -lutil -lcurl -o bin/hp

clean:
	rm src/*.o bin/hp

run:
	./bin/hp
