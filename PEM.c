#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//gcc -Wall -g PEM.c -lssl -lcrypto -o pem

void pem_aplanado (char md[]){
	BIO *b64,*bio;
	FILE *f = fopen("out.txt","w");

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(f,BIO_CLOSE);
	BIO_push(b64,bio);
	BIO_write(b64,md,strlen(md));
	BIO_flush(b64);
	BIO_free_all(b64);
}

void pem_desaplana (FILE *f){
	BIO *bio, *b64, *bio_out;
	FILE *fout = fopen("out2.txt","w");
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


int main(int argc, char *argv[]){
	char md[] = "Hello World\n";
	FILE *fin = fopen("out.txt","r");
	pem_aplanado(md);
	pem_desaplana(fin);
	
	return 0;
}
