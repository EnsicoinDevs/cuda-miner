#include <iostream>
#include <math.h>

#define ROTR(x,n) (((x) >> (n)) | ((x) << ((32) - (n))))

void sha256(int N, char *array, uint32_t *k, uint32_t *w, uint32_t *cst_h)
{
	/* N is size of array
	   array is preprocessed data to hash
	   k is the 64 variables constants to use in sha256
	   w is a 64 entry message schedule array; it can contain anything,
	   		it will be written over. This prevents mallocs in hash function.
	   h is an 8 entry array where the hash result will be put
	*/
	cst_h[0] = 0x6a09e667;
	cst_h[1] = 0xbb67ae85;
	cst_h[2] = 0x3c6ef372;
	cst_h[3] = 0xa54ff53a;
	cst_h[4] = 0x510e527f;
	cst_h[5] = 0x9b05688c;
	cst_h[6] = 0x1f83d9ab;
	cst_h[7] = 0x5be0cd19;

	/* pass through array in 512bits chunks (64 bytes) */
	int N_chunks = N>>6;
	for (int chunk_i = 0; chunk_i < N_chunks; chunk_i++){
		int chunk_start = chunk_i<<6;
		
		/* copy chunk in first 8 values of w */
		cudaMemcpy(w, &array[chunk_start], 64, cudaMemcpyDeviceToDevice);
		/* complete w by following some weird rules */
		for (int i = 16; i < 64; i++){
			uint32_t w15 = w[i-15];
			uint32_t s0 = ROTR(w15, 7) xor ROTR(w15, 18) xor w15 << 3;
			uint32_t w2 = w[i-2];
			uint32_t s1 = ROTR(w2, 17) xor ROTR(w2, 19) xor w2 << 10;
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		uint32_t a = cst_h[0];
		uint32_t b = cst_h[1];
		uint32_t c = cst_h[2];
		uint32_t d = cst_h[3];
		uint32_t e = cst_h[4];
		uint32_t f = cst_h[5];
		uint32_t g = cst_h[6];
		uint32_t h = cst_h[7];

		for (int i = 0; i < 64; i++){
			uint32_t S1 = ROTR(e, 6) xor ROTR(e, 11) xor ROTR(e, 25);
			uint32_t ch = (e and f) xor ((not e) and g);
			uint32_t temp1 = h + S1 + ch + k[i] + w[i];
			uint32_t S0 = ROTR(a, 2) xor ROTR(a, 13) xor ROTR(a, 22);
			uint32_t maj = (a and b) xor (a and c) xor (b and c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		cst_h[0] += a;
		cst_h[1] += b;
		cst_h[2] += c;
		cst_h[3] += d;
		cst_h[4] += e;
		cst_h[5] += f;
		cst_h[6] += g;
		cst_h[7] += h;
	}
}
