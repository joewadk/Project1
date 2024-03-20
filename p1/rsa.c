#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"
#include gmp.h>

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
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char* buf = malloc(len);
	Z2BYTES(buf,len,x);
	/* force little endian-ness: */
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
	unsigned char* buf = malloc(len);
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
	 
	// we make members of K that will be modified later
	
    	mpz_init(K->n);
    	mpz_init(K->e);
    	mpz_init(K->d);
	
	
	//we use a common RSA param 65537 as e for computational security 
	mpz_set_ui(K->e, 65537);
	
	
	//random long integer generation
	gmp_randstate_t r_state;
    	gmp_randinit_default(r_state);
    	gmp_randseed_ui(r_state, (unsigned long)time(NULL));
    	
    	// this should generate prime long integers p and q
	while (true) {
       		while (!ISPRIME(p)){
            		generate_random_prime(p, keyBits / 2, r_state); } 
		while (!ISPRIME(q) || mpz_cmp(p, q) == 0){  	//check if q is prime while also ensuring p and q are distinct
            		generate_random_prime(q, keyBits / 2, r_state); } 
            		
       		// Calculate n (product of p and q) and phi (product of p-1 and q-1)
		mpz_mul(K->n, p, q);  
		mpz_sub_ui(phi, p, 1);
		mpz_sub_ui(gcd, q, 1);
		mpz_mul(phi, phi, gcd);

		mpz_gcd(gcd, K->e, phi);
		if (mpz_cmp_ui(gcd, 1) == 0) {  //mpz_cmp only compares two mpz_t type integers, by using mpz_cmp_ui we can compare mpz_t type integers with long integers
		    break; //by doing gcd, we check if we do in fact have prime values (the gcd should only have factors with 1 and itself) and if not it continues looping
		    }
		// Compute the modular inverse d = e^-1 mod φ(n)
	    	if (mpz_invert(K->d, K->e, phi) == 0) {
			mpz_clears(K->n, K->e, K->d, K->p, K->q, phi, gcd, NULL);
			gmp_randclear(r_state);
	       		return -1; // Return failure
	    		}
	    		break; //termination step - p and q were found to be prime
	    }
	mpz_clears(p, q, phi, gcd, NULL);  //ensure no memory leaks occur in successive calls
    	gmp_randclear(r_state);  //clear the rand integer
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	    /* TODO: write this.  Use BYTES2Z to get integers, and then
	    * Z2BYTES to write the output buffer. */	
	
	    mpz_t msg;
	    mpz_init(msg);
	    mpz_import(msg, len, 1, sizeof(unsigned char), 0, 0, inBuf);

	    // Ensure the message is smaller than the modulus
	    if (mpz_cmp(msg, K->n) >= 0) {
		mpz_clear(msg);
		return 0;  
	    }

	    // Encrypt the message: C = m^e mod n
	    mpz_t encrypted;
	    mpz_init(encrypted);
	    mpz_powm(encrypted, msg, K->e, K->n);  // Encrypt the message

	    // Export the result back to bytes
	    size_t count = 0;
	    mpz_export(outBuf, &count, 1, sizeof(unsigned char), 0, 0, encrypted);  // Export mpz to byte array

	    // Clear the memory for future calls
	    mpz_clear(msg);
	    mpz_clear(encrypted);

	    return count; /* TODO: return should be # bytes written */
	} 
	 
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	
	mpz_t enc_msg;  //initialize the encoded message to be used for manipulation later
   	mpz_init(enc_msg);
    	mpz_import(enc_msg, len, 1, sizeof(unsigned char), 0, 0, inBuf);  //putting the bytes from encoded message buffer into the variable

    	// We will use the property m=C^d mod n to decode the cipher text
    	mpz_t decrypted;
    	mpz_init(decrypted);
    	mpz_powm(decrypted, enc_msg, K->d, K->n);  // Decrypt the message

    	// Export the result back to bytes
    	size_t count = 0;
    	mpz_export(outBuf, &count, 1, sizeof(unsigned char), 0, 0, decrypted);  // Export mpz to byte array
	
    	// Clear memory for future calls
    	mpz_clear(enc_msg);
    	mpz_clear(decrypted);

    return count; /* TODO: return should be # bytes written */

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
