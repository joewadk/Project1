#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

void setPrime(mpz_t prime, size_t bytes){
    unsigned char* buf = malloc(bytes);
    do{
        randBytes(buf, bytes);
        BYTES2Z(prime, buf, bytes);
    }while (!ISPRIME(prime));
    free(buf);
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);

	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

    size_t keyBytes = keyBits / CHAR_BIT;
    setPrime(K->p, keyBytes);
    setPrime(K->q, keyBytes);
    mpz_mul(K->n, K->p, K->q);

    mpz_t phi;
    mpz_t qSubOne;
    mpz_t pSubOne;

    mpz_init(phi);
    mpz_init(qSubOne);
    mpz_init(pSubOne);

    mpz_sub_ui(pSubOne, K->p, 1);
    mpz_sub_ui(qSubOne, K->q, 1);
    mpz_mul(phi, pSubOne, qSubOne);

    mpz_t temp;
    mpz_init(temp);
    unsigned char* tempBuf = malloc(keyBytes);

    mpz_t one;
    mpz_init(one); mpz_set_ui(one, 1);

    do{
        randBytes(tempBuf,keyBytes);
        BYTES2Z(K->e, tempBuf, keyBytes);
        mpz_gcd(temp, K->e, phi);
    }while (mpz_cmp(temp, one));

    mpz_invert(K->d, K->e , phi);

    free(tempBuf);
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
    mpz_t inInt;
    mpz_init(inInt);

    BYTES2Z(inInt, inBuf, len);

    mpz_t outInt;
    mpz_init(outInt);
    mpz_powm(outInt, inInt, K->e, K->n);

    Z2BYTES(outBuf, len, outInt);

	return len;
}

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{

    mpz_t inInt;
    mpz_init(inInt);

    BYTES2Z(inInt, inBuf, len);

    mpz_t outInt;
    mpz_init(outInt);
    mpz_powm(outInt, inInt, K->d, K->n);

    Z2BYTES(outBuf, len, outInt);

	return len;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	//gmp_printf("n %Zd\n", K->n);
	//gmp_printf("e %Zd\n", K->e);
	//gmp_printf("p %Zd\n", K->p);
	//gmp_printf("q %Zd\n", K->q);
	//gmp_printf("d %Zd\n", K->d);
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	//gmp_printf("n %Zd\n", K->n);
	//gmp_printf("e %Zd\n", K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);

	//gmp_printf("n %Zd\n", K->n);
	//gmp_printf("e %Zd\n", K->e);
	//gmp_printf("p %Zd\n", K->p);
	//gmp_printf("q %Zd\n", K->q);
	//gmp_printf("d %Zd\n", K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
