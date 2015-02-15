#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>



void initSha (SHA512_CTX *c){
	SHA512_Init(c);
}

void feedSha(SHA512_CTX *c,int fd){
	char buf[4096];
	while (read(fd, &buf, sizeof(buf)) > 0){
		SHA512_Update(c, buf, sizeof(buf));
	}
	SHA512_Final(//meterle el buffer donde lo queremos dejar,c)
}

int main(int argc, char *argv[]){
SHA512_CTX context;
int fd;
	fd = open("monete",O_RDONLY);
	initSha(&context);
	feedSha(&context,fd);

	return 0;
}
