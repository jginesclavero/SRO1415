#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>



enum{

	BUF_LENGTH = 4096,
	MSG_TO_SIGN_SIZE = 4096/8,


};

void 
initSha (SHA512_CTX *c){
	SHA512_Init(c);
}

/* -------------------- Nos hará falta más adelante -------------------
void
pem (unsigned char md[]){
	BIO *b64,*bio;
	FILE *f = fopen("hashbase64","w");

	if (f<0){
		err(1,"Open file error \n");
	}else{
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new_fp(f,BIO_CLOSE);
		BIO_push(b64,bio);
		BIO_write(b64,md,SHA512_DIGEST_LENGTH);
		BIO_flush(b64);
		BIO_free_all(b64);
	}
}

void 
pem_desaplana (){
	BIO *bio, *b64, *bio_out;
	FILE *f = fopen("hashbase64","r");
	FILE *fout = fopen("hashdesplana","w");
 	char inbuf[512];
 	int inlen;
 	b64 = BIO_new(BIO_f_base64());
 	bio = BIO_new_fp(f, BIO_NOCLOSE);
 	bio_out = BIO_new_fp(fout,BIO_CLOSE);
 	BIO_push(b64, bio);
 	while((inlen = BIO_read(b64, inbuf, 512)) > 0) //leemos de b64 y vamos metiendolo en inbuf para luego 
        BIO_write(bio_out, inbuf, inlen);			//escribirlo en el fichero (bio_out)
 	BIO_flush(bio_out);
 	BIO_free_all(b64);
}
*/

void
sign_hash(unsigned char hash[]){
	unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
									0x06, 0x09, 0x60, 0x86,
									0x48, 0x01, 0x65, 0x03,
									0x04, 0x02, 0x03, 0x05,
									0x00, 0x04, 0x40};
	
	unsigned char msg[MSG_TO_SIGN_SIZE];
	//usar memcpy y aritmetica de punteros
	memcpy(hash,msg);

}




void 
feedSha(SHA512_CTX *c,int fd,char *file_path){
	int i;
	int l;
	char *buf = malloc(BUF_LENGTH);
	unsigned char md[SHA512_DIGEST_LENGTH];

	while ((l = read(fd, buf, BUF_LENGTH)) > 0){
		SHA512_Update(c, buf, l);
	}

	if(l < 0)
		err(1, "read error");

	SHA512_Update(c, file_path, strlen(file_path)); //Alimentamos sha512 con el nombre del fichero
	SHA512_Final(md,c);
	free(buf);

	

	for (i=0;i< sizeof(md);i++){
		printf("%02x", md[i]);
	}
	printf("\n");

	//pem(md);
	//pem_desaplana();
	/* ---------------------------------------Firmamos la hash en crudo -----------------------------------*/

	sign_hash(md);


}


int 
main(int argc, char *argv[]){
SHA512_CTX context;
int fd;
char *file_path;

	if(argc < 1){
		err(1, "arg error");
		return 0;
	}else{
		file_path = argv[1];
	}

	fd = open(file_path,O_RDONLY);
	initSha(&context);
	feedSha(&context,fd,file_path);

	return 0;
}
