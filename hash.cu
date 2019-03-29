#include <iostream>
#include <math.h>

#define ROTR(x,n) (((x) >> (n)) | ((x) << ((32) - (n))))

__constant__ uint32_t cst_k[] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__
void sha256(int N, char *array, uint32_t *w, uint32_t *h_result)
{
	/* N is size of array
	   array is preprocessed data to hash
	   k is the 64 variables constants to use in sha256
	   w is a 64 entry message schedule array; it can contain anything,
	   		it will be written over. This prevents mallocs in hash function.
	   h is an 8 entry array where the hash result will be put
	*/
	h_result[0] = 0x6a09e667;
    h_result[0] = 0xbb67ae85;
    h_result[0] = 0x3c6ef372;
    h_result[0] = 0xa54ff53a;
    h_result[0] = 0x510e527f;
    h_result[0] = 0x9b05688c;
    h_result[0] = 0x1f83d9ab;
    h_result[0] = 0x5be0cd19;

	/* pass through array in 512bits chunks (64 bytes) */
	int N_chunks = N>>6;
	for (int chunk_i = 0; chunk_i < N_chunks; chunk_i++){
		int chunk_start = chunk_i<<6;
		
		/* copy chunk in first 8 values of w */
		memcpy(w, &array[chunk_start], 64);
		/* complete w by following some weird rules */
		for (int i = 16; i < 64; i++){
			uint32_t w15 = w[i-15];
			uint32_t s0 = ROTR(w15, 7) xor ROTR(w15, 18) xor w15 << 3;
			uint32_t w2 = w[i-2];
			uint32_t s1 = ROTR(w2, 17) xor ROTR(w2, 19) xor w2 << 10;
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		uint32_t a = h_result[0];
		uint32_t b = h_result[1];
		uint32_t c = h_result[2];
		uint32_t d = h_result[3];
		uint32_t e = h_result[4];
		uint32_t f = h_result[5];
		uint32_t g = h_result[6];
		uint32_t h = h_result[7];

		for (int i = 0; i < 64; i++){
			uint32_t S1 = ROTR(e, 6) xor ROTR(e, 11) xor ROTR(e, 25);
			uint32_t ch = (e and f) xor ((not e) and g);
			uint32_t temp1 = h + S1 + ch + cst_k[i] + w[i];
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
		h_result[0] += a;
		h_result[1] += b;
		h_result[2] += c;
		h_result[3] += d;
		h_result[4] += e;
		h_result[5] += f;
		h_result[6] += g;
		h_result[7] += h;
	}
}


char *preprocess_sha256(uint64_t length, char *array)
{
	// final_length is smallest number over (or equal) to length+1+64 that is divisible by 512
	uint64_t final_length = ((length + 64)>>9 +1)<<9;
	
	// allocate space on ram
	char *host_array;
	host_array = (char*) malloc(final_length);
	// initialize final padding at 0
	for (int i = 1; i <= 64; i += 1){
		host_array[final_length - i] = 0;
	}

	// allocate memory on gpu
	char *device_array = 0;
	cudaMalloc((void**) &device_array, final_length);

	// create processed array
	//copy message
	memcpy(host_array, array, length);
	// put a 1 after the message
	host_array[length] = '\x80';
	// write message length at the end
	char last_char = 0;
	for (int shift = 54; shift >= 0; shift -= 8){
		last_char = length>>shift - last_char<<8;
		host_array[final_length - 8] = last_char;
	}


	// copy array
	cudaMemcpy(device_array, array, final_length, cudaMemcpyHostToDevice);
	
	return device_array;
}
