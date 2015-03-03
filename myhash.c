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
	MSG_TO_SIGN_SIZE = (4096/8),


};

void 
initSha(SHA512_CTX *c){
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
create_msg(unsigned char msg[],unsigned char hash[]){
	unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
									0x06, 0x09, 0x60, 0x86,
									0x48, 0x01, 0x65, 0x03,
									0x04, 0x02, 0x03, 0x05,
									0x00, 0x04, 0x40};
	int ID_len = sizeof(EMSASHA512ID);
	int t_len = SHA512_DIGEST_LENGTH + ID_len;
	unsigned char T[t_len];
	int ps_len = MSG_TO_SIGN_SIZE-t_len-3;
	unsigned char PS[ps_len];
	char *aux = NULL;
	int i;
	memcpy(T,EMSASHA512ID,ID_len);
	aux = T + ID_len;
	memcpy(aux,hash,SHA512_DIGEST_LENGTH);
	
	for (i=0;i< ps_len;i++){
		PS[i] = 0xFF;
	}
	unsigned char zero[] = {0x00};
	unsigned char one[] = {0x01};
	memcpy(msg,zero,sizeof(zero));
	aux = msg + sizeof(zero);
	memcpy(aux,one,sizeof(one));
	aux = aux + sizeof(one);
	memcpy(aux,PS,ps_len);
	aux=aux+ps_len;
	memcpy(aux,zero,sizeof(zero));
	aux=aux+sizeof(zero);
	memcpy(aux,T,t_len);

}




void
sign_hash(unsigned char hash[], RSA *RSA_key){
	
	unsigned char msg[MSG_TO_SIGN_SIZE];
	create_msg(msg,hash);
	int rsa_size = RSA_size(RSA_key);
	unsigned char sign[rsa_size];
	RSA_private_encrypt(MSG_TO_SIGN_SIZE,msg,sign,RSA_PKCS1_PADDING);

}




void 
feedSha(SHA512_CTX *c,int fd,char *file_path,unsigned char md[]){
	int i,l;
	char *buf = malloc(BUF_LENGTH);
	

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
}

int 
main(int argc, char *argv[]){
SHA512_CTX context;
int fd;
char *file_path;
unsigned char md[SHA512_DIGEST_LENGTH];
RSA *RSA_key;

	if(argc < 2){
		err(1, "arg error");
		return 0;
	}else{
		file_path = argv[1];
		RSA_key = argv[2];   //Falta parsear o hacer algo para que sea RSA un fichero que le pasemos 
	}

	fd = open(file_path,O_RDONLY);
	initSha(&context);
	feedSha(&context,fd,file_path,md);
	sign_hash(md,RSA_key);

	return 0;
}
