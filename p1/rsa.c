#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"
#include <gmp.h>
#include <time.h>

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
	unsigned char* buf = (unsigned char*)malloc(len);
	Z2BYTES(buf,len,x);

	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
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
	unsigned char* buf = (unsigned char*)malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// initializing the primes p and q, euler's totient, and the gcd (will be assigned later) that determines if e and the totient are coprime
	mpz_t p, q, phi, gcd;
	mpz_inits(p, q, phi, gcd, NULL);

	// Initialize members of K for use
	mpz_init(K->n);
	mpz_init(K->e);
	mpz_init(K->d);

	// Common RSA parameter 65537 used as e for simplicity and security
	mpz_set_ui(K->e, 65537);

	// Setting up the random state for prime number generation
	gmp_randstate_t r_state;
	gmp_randinit_default(r_state);
	gmp_randseed_ui(r_state, (unsigned long)time(NULL));

	// The flag to indicate if suitable primes have been found
	int primes_found = 0;
	while (!primes_found) {
		// Generate prime p
		while (1) {
		    mpz_urandomb(p, r_state, keyBits / 2); // Generate a random number of keyBits/2 length
		    mpz_setbit(p, keyBits / 2 - 1);       // Ensure it is of the correct length
		    mpz_nextprime(p, p);                  // Get the next prime starting from p
		    if (ISPRIME(p)) {
		        break;  // Exit loop if p is a prime
		    }
		}

		// Generate prime q, distinct from p
		while (1) {
		    mpz_urandomb(q, r_state, keyBits / 2);
		    mpz_setbit(q, keyBits / 2 - 1);
		    mpz_nextprime(q, q);  // Ensure q is a prime number
		    if (mpz_cmp(p, q) != 0 && ISPRIME(q)) {
		        break;  // Exit loop if q is a prime and distinct from p
		    }
		}

		// Calculate n (product of p and q) and phi (product of p-1 and q-1)
		mpz_mul(K->n, p, q);  // n = p * q
		mpz_sub_ui(phi, p, 1);
		mpz_sub_ui(gcd, q, 1);
		mpz_mul(phi, phi, gcd);  // phi = (p-1)*(q-1)

		// Check if e and phi are coprime
		mpz_gcd(gcd, K->e, phi);
		if (mpz_cmp_ui(gcd, 1) == 0) {
		    // Compute the modular inverse d = e^-1 mod φ(n)
		    if (mpz_invert(K->d, K->e, phi) != 0) {
		        primes_found = 1; // Indicate that suitable primes have been found
		    }
		}
	    }

	    // Cleanup and free allocated memory
	    mpz_clears(p, q, phi, gcd, NULL);
	    gmp_randclear(r_state);
	    return 0; // Success
	}


size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	    /* TODO: write this.  Use BYTES2Z to get integers, and then
	    * Z2BYTES to write the output buffer. */	
	
	    mpz_t msg;
	    mpz_init(msg);
	    BYTES2Z(msg, inBuf, len);

	    
	    // Encrypt the message: C = m^e mod n
	    mpz_t encrypted;
	    mpz_init(encrypted);
	    mpz_powm(encrypted, msg, K->e, K->n);  // Encrypt the message

	    // Export the result back to bytes
	    Z2BYTES(outBuf, len, encrypted);
	    return len; /* TODO: return should be # bytes written */
	} 
	 
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	
	mpz_t enc_msg;  //initialize the encoded message to be used for manipulation later
   	mpz_init(enc_msg);
    	BYTES2Z(enc_msg, inBuf, len);  //putting the bytes from encoded message buffer into the variable

    	// We will use the property m=C^d mod n to decode the cipher text
    	mpz_t decrypted;
    	mpz_init(decrypted);
    	mpz_powm(decrypted, enc_msg, K->d, K->n);  // Decrypt the message

    	// Export the result back to bytes
    	Z2BYTES(outBuf, len, decrypted);

    return len; /* TODO: return should be # bytes written */

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
