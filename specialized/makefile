all:
	gcc -o patch patch.c 
	gcc -o target target.c -s

patch:
	gcc -o patch patch.c 

target:
	gcc -o target target.c -s

clean:
	rm -f target patch output