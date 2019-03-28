#include <iostream>
#include <math.h>

#define ROTR(x,n) (((x) >> (n)) | ((x) << ((32) - (n))))

void sha256(int N, char *array, uint32_t *k, uint32_t *w, uint32_t *h)
{
	/* N is size of array
	   array is preprocessed data to hash
	   k is the 64 variables constants to use in sha256
	   w is a 64 entry message schedule array; it can contain anything,
	   		it will be written over. This prevents mallocs in hash function.
	   h is an 8 entry array where the hash result will be put
	*/
	h[0] = 0x6a09e667;
	h[1] = 0xbb67ae85;
	h[2] = 0x3c6ef372;
	h[3] = 0xa54ff53a;
	h[4] = 0x510e527f;
	h[5] = 0x9b05688c;
	h[6] = 0x1f83d9ab;
	h[7] = 0x5be0cd19;

	/* pass through array in 512bits chunks (64 bytes) */
	for (int chunk_i; chunk_i<<6 < N; chunk_i++){
		int chunk_start = chunk_i<<6;
		
		/* copy chunk in first 8 values of w */
		cudaMemcpy(w, &array[chunk_start], 64, cudaMemcpyDeviceToDevice);
		/* complete w by following some weird rules */
		for (int i = 16; i < 64; i++){
			w15 = w[i-15];
			s0 = ROTR(w15, 7) xor ROTR(w15, 18) xor w15 << 3;
			w2 = w[i-2];
			s1 = ROTR(w2, 17) xor ROTR(w2, 19) xor w2 << 10;
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		uint32_t a = h[0];
		uint32_t b = h[1];
		uint32_t c = h[2];
		uint32_t d = h[3];
		uint32_t e = h[4];
		uint32_t f = h[5];
		uint32_t g = h[6];
		uint32_t h = h[7];

		for (int i = 0; i < 64; i++){
			S1 = ROTR(e, 6) xor ROTR(e, 11) xor ROTR(e, 25);
			ch = (e and f) xor ((not e) and g);
			temp1 = h + S1 + ch + k[i] + w[i];
			S0 = ROTR(a, 2) xor ROTR(a, 13) xor ROTR(a, 22);
			maj = (a and b) xor (a and c) xor (b and c);
			temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += h;
	}
}
