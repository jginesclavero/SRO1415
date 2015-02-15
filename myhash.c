#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>




void initSha (SHA512_CTX *c){
	SHA512_Init(c);
}

void feedSha(SHA512_CTX *c,int fd){
	int i;
	char buf = malloc(4096);
	unsigned char md[SHA512_DIGEST_LENGTH];
	while (read(fd, &buf, sizeof(buf)) > 0){
		SHA512_Update(c, &buf, sizeof(buf));
	}
	SHA512_Final(md,c);

	for (i=0;i< sizeof(md);i++){
		printf("%02x", md[i]);
	}
}

int main(int argc, char *argv[]){
SHA512_CTX context;
int fd;
	fd = open("monete",O_RDONLY);
	initSha(&context);
	feedSha(&context,fd);

	return 0;
}
