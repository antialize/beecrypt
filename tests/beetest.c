/*
 * beetest.c
 *
 * BeeCrypt test and benchmark application
 *
 * Copyright (c) 1999, 2000, 2001, 2002 Virtual Unlimited B.V.
 *
 * Author: Bob Deblier <bob@virtualunlimited.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "beecrypt.h"
#include "blockmode.h"
#include "aes.h"
#include "blowfish.h"
#include "mp32barrett.h"
#include "dhaes.h"
#include "dlkp.h"
#include "dsa.h"
#include "elgamal.h"
#include "hmacmd5.h"
#include "md5.h"
#include "rsa.h"
#include "sha1.h"
#include "sha256.h"
#include "mp32.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_STRING_H
# include <string.h>
#endif
#if HAVE_ERRNO_H
# include <errno.h>
#endif
#if HAVE_TIME_H
# include <time.h>
#endif

#include <stdio.h>

static const char* dsa_p = "8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291";
static const char* dsa_q = "c773218c737ec8ee993b4f2ded30f48edace915f";
static const char* dsa_g = "626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802";
static const char* dsa_x = "2070b3223dba372fde1c0ffc7b2e3b498b260614";
static const char* dsa_y = "19131871d75b1612a819f29d78d1b0d7346f7aa77bb62a859bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74858fba33f44c06699630a76b030ee333";
static const char* elg_n = "8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80290";

int testVectorMul()
{
	uint32 a[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
	uint32 r[8];

	mp32zero(8, r);
	mp32sqr(r, 4, a);

	printf("done\n");

	return 0;
}

int testVectorInvMod(const dlkp_p* keypair)
{
	randomGeneratorContext rngc;

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		register int rc;

		register uint32  size = keypair->param.p.size;
		register uint32* temp = (uint32*) malloc((8*size+6) * sizeof(uint32));

		mp32brndinv_w(&keypair->param.n, &rngc, temp, temp+size, temp+2*size);

		mp32bmulmod_w(&keypair->param.n, size, temp, size, temp+size, temp, temp+2*size);

		rc = mp32isone(size, temp);

		free(temp);

		randomGeneratorContextFree(&rngc);

		return rc;
	}
	return -1;
}

int testVectorExpMod(const dlkp_p* keypair)
{
	int rc;
	mp32number y;
	
	mp32nzero(&y);
	
	mp32bnpowmod(&keypair->param.p, &keypair->param.g, &keypair->x, &y);

	rc = mp32eqx(y.size, y.data, keypair->y.size, keypair->y.data);

	mp32nfree(&y);

	return rc;
}

int testVectorDSA(const dlkp_p* keypair)
{
	int rc = 0;

	randomGeneratorContext rngc;

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		mp32number digest, r, s;

		mp32nzero(&digest);
		mp32nzero(&r);
		mp32nzero(&s);

		mp32nsize(&digest, 5);

		rngc.rng->next(rngc.param, digest.data, digest.size);

		dsasign(&keypair->param.p, &keypair->param.q, &keypair->param.g, &rngc, &digest, &keypair->x, &r, &s);

		rc = dsavrfy(&keypair->param.p, &keypair->param.q, &keypair->param.g, &digest, &keypair->y, &r, &s);

		mp32nfree(&digest);
		mp32nfree(&r);
		mp32nfree(&s);

		randomGeneratorContextFree(&rngc);
	}
	return rc;
}

int testVectorElGamalV1(const dlkp_p* keypair)
{
	int rc = 0;

	randomGeneratorContext rngc;

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		mp32number digest, r, s;

		mp32nzero(&digest);
		mp32nzero(&r);
		mp32nzero(&s);

		mp32nsize(&digest, 5);

		rngc.rng->next(rngc.param, digest.data, digest.size);

		elgv1sign(&keypair->param.p, &keypair->param.n, &keypair->param.g, &rngc, &digest, &keypair->x, &r, &s);

		rc = elgv1vrfy(&keypair->param.p, &keypair->param.n, &keypair->param.g, &digest, &keypair->y, &r, &s);

		mp32nfree(&digest);
		mp32nfree(&r);
		mp32nfree(&s);

		randomGeneratorContextFree(&rngc);
	}
	return rc;
}

int testVectorElGamalV3(const dlkp_p* keypair)
{
	int rc = 0;

	randomGeneratorContext rngc;

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		mp32number digest, r, s;

		mp32nzero(&digest);
		mp32nzero(&r);
		mp32nzero(&s);

		mp32nsize(&digest, 5);

		rngc.rng->next(rngc.param, digest.data, digest.size);

		elgv3sign(&keypair->param.p, &keypair->param.n, &keypair->param.g, &rngc, &digest, &keypair->x, &r, &s);

		rc = elgv3vrfy(&keypair->param.p, &keypair->param.n, &keypair->param.g, &digest, &keypair->y, &r, &s);

		mp32nfree(&digest);
		mp32nfree(&r);
		mp32nfree(&s);

		randomGeneratorContextFree(&rngc);
	}
	return rc;
}

#if 0
int testVectorDHAES(const dlkp_p* keypair)
{
	/* try encrypting and decrypting a randomly generated message */

	int rc = 0;

	dhaes_p dh;

	/* incomplete */
	if (dhaes_pInit(&dh, &keypair->param) == 0)
	{
		mp32number mkey, mac;

		memchunk src, *dst, *cmp;

		/* make a random message of 2K size */
		src.size = 2048;
		src.data = (byte*) malloc(src.size);
		memset(src.data, 1, src.size);

		/* initialize the message key and mac */
		mp32nzero(&mkey);
		mp32nzero(&mac);

		/* encrypt the message */
		dst = dhaes_pEncrypt(&dh, &keypair->y, &mkey, &mac, &src);
		/* decrypt the message */
		cmp = dhaes_pDecrypt(&dh, &keypair->x, &mkey, &mac, dst);

		if (cmp != (memchunk*) 0)
		{
			if (src.size == cmp->size)
			{
				if (memcmp(src.data, cmp->data, src.size) == 0)
					rc = 1;
			}

			free(cmp->data);
			free(cmp);
		}

		free(dst->data);
		free(dst);
		free(src.data);

		dhaes_pFree(&dh);

		return rc;
	}

	return -1;
}
#endif

int testVectorRSA()
{
	int rc = 0;

	randomGeneratorContext rngc;

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		rsakp kp;
		mp32number digest, s, scrt;

		rsakpInit(&kp);
		printf("making RSA CRT keypair\n");
		rsakpMake(&kp, &rngc, 8);
		printf("RSA CRT keypair generated\n");

		mp32nzero(&digest);
		mp32nzero(&s);
		mp32nzero(&scrt);

		mp32bnrnd(&kp.p, &rngc, &digest);

		if (rsapri(&kp, &digest, &s) == 0)
		{
			printf("RSA sig is ");
			mp32println(s.size, s.data);
		}

		if (rsapricrt(&kp, &digest, &scrt) == 0)
		{
			printf("RSA crt sig is ");
			mp32println(s.size, s.data);
		}

		if (mp32eqx(s.size, s.data, scrt.size, scrt.data) == 0)
		{
			printf("sig and crt sig are identical\n");
			rc = rsavrfy((rsapk*) &kp, &digest, &s);
		}

		mp32nfree(&digest);
		mp32nfree(&s);

		rsakpFree(&kp);

		randomGeneratorContextFree(&rngc);

		return rc;
	}
	return -1;
}

int testVectorDLDP()
{
	/* try generating dldp_p parameters, then see if the order of the generator is okay */
	randomGeneratorContext rc;
	dldp_p dp;

	memset(&dp, 0, sizeof(dldp_p));

	if (randomGeneratorContextInit(&rc, randomGeneratorDefault()) == 0)
	{
		register int result;
		mp32number gq;

		mp32nzero(&gq);

		dldp_pgoqMake(&dp, &rc, 768 >> 5, 512 >> 5, 1);

		/* we have the parameters, now see if g^q == 1 */
		mp32bnpowmod(&dp.p, &dp.g, (mp32number*) &dp.q, &gq);
		result = mp32isone(gq.size, gq.data);

		mp32nfree(&gq);
		dldp_pFree(&dp);

		randomGeneratorContextFree(&rc);

		return result;
	}
	return 0;
}

int testVectorAES()
{
	uint8 k[24] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};

	uint8 src[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};

	uint8 dst[16];

	uint32 key[6];

	aesParam param;

	decodeInts(key, k, 4);

	aesSetup(&param, key, 128, ENCRYPT);

	aesEncrypt(&param, (uint32*) dst, (const uint32*) src);

	decodeInts(key, src, 4);
	printf("src: "); mp32println(4, key);
	decodeInts(key, dst, 4);
	printf("dst: "); mp32println(4, key);

	printf("\n");

	decodeInts(key, k, 4);
	mp32println(4, key);

	aesSetup(&param, key, 128, DECRYPT);
	mp32println(4, (const uint32*) dst);
	aesDecrypt(&param, (uint32*) src, (const uint32*) dst);

	decodeInts(key, src, 4);
	mp32println(4, key);

	return 0;
}

int testVectorMD5()
{
	uint32 expect[4] = { 0x90015098, 0x3cd24fb0, 0xd6963f7d, 0x28e17f72 };
	uint32 digest[4];
	md5Param param;

	md5Reset(&param);
	md5Update(&param, (const unsigned char*) "abc", 3);
	md5Digest(&param, digest);

	return mp32eq(4, expect, digest);
}

int testVectorSHA1()
{
	uint32 expect[5] = { 0xA9993E36, 0x4706816A, 0xBA3E2571, 0x7850C26C, 0x9CD0D89D };
	uint32 digest[5];
	sha1Param param;
	
	sha1Reset(&param);
	sha1Update(&param, (const unsigned char*) "abc", 3);
	sha1Digest(&param, digest);

	return mp32eq(5, expect, digest);
}

int testVectorSHA256()
{
	uint32 expect[8] = { 0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad };
	uint32 digest[8];
	sha256Param param;
	
	sha256Reset(&param);
	sha256Update(&param, (const unsigned char*) "abc", 3);
	sha256Digest(&param, digest);

	return mp32eq(8, expect, digest);
}

uint32 keyValue[] = 
{
	0x00010203,
	0x04050607,
	0x08090a0b,
	0x0c0d0e0f,
	0x10111213,
	0x14151617,
	0x18191a1b,
	0x1c1d1e1f,
	0x20212223,
	0x24252627,
	0x28292a2b,
	0x2c2d2e2f,
	0x30313233,
	0x34353637,
	0x38393a3b,
	0x3c3d3e3f
};
	
void testBlockInit(uint8* block, int length)
{
	register int i;
	for (i = 1; i <= length; i++)
		*(block++) = (uint8) i;
}

void testBlockCiphers()
{
	int i, k;

	printf("Timing the blockciphers:\n");

	for (i = 0; i < blockCipherCount(); i++)
	{
		const blockCipher* tmp = blockCipherGet(i);

		if (tmp)
		{
			uint32 blockwords = tmp->blocksize >> 2;

			uint32* src_block = (uint32*) malloc(2 * blockwords * sizeof(uint32));
			uint32* enc_block = (uint32*) malloc(2 * blockwords * sizeof(uint32));
			uint32* dec_block = (uint32*) malloc(2 * blockwords * sizeof(uint32));
			uint32* spd_block = (uint32*) malloc(1024 * 1024 * blockwords * sizeof(uint32));

			void* encrypt_param = (void*) malloc(tmp->paramsize);
			void* decrypt_param = (void*) malloc(tmp->paramsize);

			printf("  %s:\n", tmp->name);

			for (k = tmp->keybitsmin; k <= tmp->keybitsmax; k += tmp->keybitsinc)
			{
				printf("    setup encrypt (%d bits key): ", k);
				if (tmp->setup(encrypt_param, keyValue, k, ENCRYPT) < 0)
				{
					printf("failed\n");
					continue;
				}
				printf("ok\n");
				printf("    setup decrypt (%d bits key): ", k);
				if (tmp->setup(decrypt_param, keyValue, k, DECRYPT) < 0)
				{
					printf("failed\n");
					continue;
				}
				printf("ok\n");
				printf("    encrypt/decrypt test block: ");
				testBlockInit((uint8*) src_block, tmp->blocksize >> 2);

				blockEncrypt(tmp, encrypt_param, CBC, 2, enc_block, src_block);
				blockDecrypt(tmp, decrypt_param, CBC, 2, dec_block, enc_block);

				if (memcmp(dec_block, src_block, tmp->blocksize >> 2))
				{
					printf("failed\n");
					// continue;
				}
				printf("ok\n");
				printf("    speed measurement:\n");
				{
					#if HAVE_TIME_H
					double ttime;
					clock_t tstart, tstop;
					#endif

					#if HAVE_TIME_H
					tstart = clock();
					#endif
					blockEncrypt(tmp, encrypt_param, ECB, 1024 * 1024, spd_block, spd_block);
					#if HAVE_TIME_H
					tstop = clock();
					ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
					printf("      ECB encrypts 1M blocks of %d bits in %.3f seconds (%.3f MB/s)\n", tmp->blocksize << 3, ttime, (tmp->blocksize) / ttime);
					#endif
					#if HAVE_TIME_H
					tstart = clock();
					#endif
					blockDecrypt(tmp, decrypt_param, ECB, 1024 * 1024, spd_block, spd_block);
					#if HAVE_TIME_H
					tstop = clock();
					ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
					printf("      ECB decrypts 1M blocks of %d bits in %.3f seconds (%.3f MB/s)\n", tmp->blocksize << 3, ttime, (tmp->blocksize) / ttime);
					#endif
					#if HAVE_TIME_H
					tstart = clock();
					#endif
					blockEncrypt(tmp, encrypt_param, CBC, 1024 * 1024, spd_block, spd_block);
					#if HAVE_TIME_H
					tstop = clock();
					ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
					printf("      CBC encrypts 1M blocks of %d bits in %.3f seconds (%.3f MB/s)\n", tmp->blocksize << 3, ttime, (tmp->blocksize) / ttime);
					#endif
					#if HAVE_TIME_H
					tstart = clock();
					#endif
					blockDecrypt(tmp, decrypt_param, CBC, 1024 * 1024, spd_block, spd_block);
					#if HAVE_TIME_H
					tstop = clock();
					ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
					printf("      CBC decrypts 1M blocks of %d bits in %.3f seconds (%.3f MB/s)\n", tmp->blocksize << 3, ttime, (tmp->blocksize) / ttime);
					#endif
				}
			}
			free(spd_block);
			free(dec_block);
			free(enc_block);
			free(src_block);
			free(decrypt_param);
			free(encrypt_param);
		}
	}
}

void testHashFunctions()
{
	int i, j;

	uint8* data = (uint8*) malloc(32 * 1024 * 1024);

	if (data)
	{
		hashFunctionContext hfc;

		printf("Timing the hash functions:\n");

		for (i = 0; i < hashFunctionCount(); i++)
		{
			const hashFunction* tmp = hashFunctionGet(i);

			if (tmp)
			{
				#if HAVE_TIME_H
				double ttime;
				clock_t tstart, tstop;
				#endif
				mp32number digest;

				mp32nzero(&digest);

				printf("  %s:\n", tmp->name);

				if (hashFunctionContextInit(&hfc, tmp) == 0)
				{
					for (j = 0; j < 4; j++)
					{
						#if HAVE_TIME_H
						tstart = clock();
						#endif

						hashFunctionContextUpdate(&hfc, data, 32 * 1024 * 1024);
						hashFunctionContextDigest(&hfc, &digest);

						#if HAVE_TIME_H
						tstop = clock();
						ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
						printf("    hashes 32 MB in %.3f seconds (%.3f MB/s)\n", ttime, 32.0 / ttime);
						#endif
					}

					hashFunctionContextFree(&hfc);
				}

				mp32nfree(&digest);
			}
		}
	}
}

void testExpMods()
{
	static const char* p_512 = "ffcf0a0767f18f9b659d92b9550351430737c3633dc6ae7d52445d937d8336e07a7ccdb119e9ab3e011a8f938151230e91187f84ac05c3220f335193fc5e351b";

	static const char* p_768 = "f9c3dc0b8e199094e3e69386e01de863908348196d6ad2557065e6ba36d10412579f394d1114c954ee647c84551d52f214e1e1682a75e7074b91085cfaf20b2888aa056bf760948a0b678bc253633eccfca86556ddb90f000ef93041b0d53171";

	static const char* p_1024 = "c615c47a56b47d869010256171ab164525f2ef4b887a4e0cdfc87043a9dd8894f2a18fa56729448e700f4b7420470b61257d11ecefa9ff518dc9fed5537ec6a9665ba73c948674320ff61b29c4cfa61e5baf47dfc1b80939e1bffb51787cc3252c4d1190a7f13d1b0f8d4aa986571ce5d4de5ecede1405e9bc0b5bf040a46d99";

	randomGeneratorContext rngc;

	mp32barrett p;
	mp32number tmp;
	mp32number g;
	mp32number x;
	mp32number y;

	mp32bzero(&p);
	mp32nzero(&g);
	mp32nzero(&x);
	mp32nzero(&y);
	mp32nzero(&tmp);

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		int i;
		#if HAVE_TIME_H
		double ttime;
		clock_t tstart, tstop;
		#endif
		
		printf("Timing modular exponentiations:\n");
		printf("  (512 bits ^ 512 bits) mod 512 bits:");
		mp32nsethex(&tmp, p_512);
		mp32bset(&p, tmp.size, tmp.data);
		mp32nsize(&g, p.size);
		mp32nsize(&x, p.size);
		mp32bnrnd(&p, &rngc, &g);
		mp32bnrnd(&p, &rngc, &x);
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
			mp32bnpowmod(&p, &g, &x, &y);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    100x in %.3f seconds\n", ttime);
		#endif
		printf("  (768 bits ^ 768 bits) mod 768 bits:");
		mp32nsethex(&tmp, p_768);
		mp32bset(&p, tmp.size, tmp.data);
		mp32nsize(&g, p.size);
		mp32nsize(&x, p.size);
		mp32bnrnd(&p, &rngc, &g);
		mp32bnrnd(&p, &rngc, &x);
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
			mp32bnpowmod(&p, &g, &x, &y);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    100x in %.3f seconds\n", ttime);
		#endif
		printf("  (1024 bits ^ 1024 bits) mod 1024 bits:");
		mp32nsethex(&tmp, p_1024);
		mp32bset(&p, tmp.size, tmp.data);
		mp32nsize(&g, p.size);
		mp32nsize(&x, p.size);
		mp32bnrnd(&p, &rngc, &g);
		mp32bnrnd(&p, &rngc, &x);
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
			mp32bnpowmod(&p, &g, &x, &y);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf(" 100x in %.3f seconds\n", ttime);
		#endif
		/* now run a test with x having 160 bits */
		mp32nsize(&x, 5);
		rngc.rng->next(rngc.param, x.data, x.size);
		printf("  (1024 bits ^ 160 bits) mod 1024 bits:");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
			mp32bnpowmod(&p, &g, &x, &y);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("  100x in %.3f seconds\n", ttime);
		#endif
		mp32bfree(&p);
		mp32nfree(&g);
		mp32nfree(&x);
		mp32nfree(&y);
		mp32nfree(&tmp);

		randomGeneratorContextFree(&rngc);
	}
	else
		printf("random generator setup problem\n");
}

void testRSA()
{
	randomGeneratorContext rngc;
	mp32number hm, s;
	rsakp kp;

	mp32nzero(&hm);
	mp32nzero(&s);

	printf("Timing RSA:\n");

	rsakpInit(&kp);

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		int i;

		#if HAVE_TIME_H
		double ttime;
		clock_t tstart, tstop;
		#endif

		printf("  generating 1024 bit crt keypair\n");

		#if HAVE_TIME_H
		tstart = clock();
		#endif
		rsakpMake(&kp, &rngc, (1024 >> 5));
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    done in %.3f seconds\n", ttime);
		#endif

		mp32nsize(&hm, 4);
		rngc.rng->next(rngc.param, hm.data, hm.size);

		printf("  RSA sign:");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
		{
			rsapricrt(&kp, &hm, &s);
		}
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("   100x in %.3f seconds\n", ttime);
		#endif

		printf("  RSA verify:");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
		{
			rsavrfy((rsapk*) &kp, &hm, &s);
		}
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf(" 100x in %.3f seconds\n", ttime);
		#endif

		rsakpFree(&kp);
		randomGeneratorContextFree(&rngc);
	}
}

void testDLAlgorithms()
{
	randomGeneratorContext rngc;
	mp32number hm, r, s;
	dldp_p dp;
	dlkp_p kp;

	mp32nzero(&hm);
	mp32nzero(&r);
	mp32nzero(&s);

	dldp_pInit(&dp);
	dlkp_pInit(&kp);

	printf("Timing Discrete Logarithm algorithms:\n");

	if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
	{
		int i;

		#if HAVE_TIME_H
		double ttime;
		clock_t tstart, tstop;
		#endif
		printf("  generating P (1024 bits) Q (160 bits) G with order Q\n");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		dldp_pgoqMake(&dp, &rngc, 1024 >> 5, 160 >> 5, 1);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    done in %.3f seconds\n", ttime);
		#endif

		dlkp_pInit(&kp);
		printf("  generating keypair\n");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		dlkp_pPair(&kp, &rngc, &dp);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    done in %.3f seconds\n", ttime);
		#endif

		mp32nsize(&hm, 5);
		rngc.rng->next(rngc.param, hm.data, hm.size);
		
		printf("  DSA sign:");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
		{
			dsasign(&kp.param.p, &kp.param.q, &kp.param.g, &rngc, &hm, &kp.x, &r, &s);
		}
        #if HAVE_TIME_H
        tstop = clock();
        ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
        printf("   100x in %.3f seconds\n", ttime);
        #endif

		printf("  DSA verify:");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		for (i = 0; i < 100; i++)
		{
			dsavrfy(&kp.param.p, &kp.param.q, &kp.param.g, &hm, &kp.y, &r, &s);
		}
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf(" 100x in %.3f seconds\n", ttime);
		#endif
		dlkp_pFree(&kp);
		dldp_pFree(&dp);

		printf("  generating P (1024 bits) Q (768 bits) G with order (P-1)\n");
		#if HAVE_TIME_H
		tstart = clock();
		#endif
		dldp_pgonMake(&dp, &rngc, 1024 >> 5, 768 >> 5);
		#if HAVE_TIME_H
		tstop = clock();
		ttime = ((double)(tstop - tstart)) / CLOCKS_PER_SEC;
		printf("    done in %.3f seconds\n", ttime);
		#endif
		dldp_pFree(&dp);

		randomGeneratorContextFree(&rngc);
	}
}

#if 0
int main()
{
	dlkp_p keypair;

	if (testVectorMD5())
		printf("MD5 works!\n");
	else
		exit(1);

	if (testVectorSHA1())
		printf("SHA-1 works!\n");
	else
		exit(1);

	if (testVectorSHA256())
		printf("SHA-256 works!\n");
	else
		exit(1);

	if (testVectorAES())
		printf("AES works!\n");
	else
		exit(1);

	dlkp_pInit(&keypair);

	mp32bsethex(&keypair.param.p, dsa_p);
	mp32bsethex(&keypair.param.q, dsa_q);
	mp32nsethex(&keypair.param.g, dsa_g);
	mp32bsethex(&keypair.param.n, elg_n);
	mp32nsethex(&keypair.y, dsa_y);
	mp32nsethex(&keypair.x, dsa_x);

	if (testVectorInvMod(&keypair))
		printf("InvMod works!\n");
	else
		exit(1);

	if (testVectorExpMod(&keypair))
		printf("ExpMod works!\n");
	else
		exit(1);

	if (testVectorDSA(&keypair))
		printf("DSA works!\n");
	else
		exit(1);

	if (testVectorElGamalV1(&keypair))
		printf("ElGamal v1 works!\n");
	else
		exit(1);

	if (testVectorElGamalV3(&keypair))
		printf("ElGamal v3 works!\n");
	else
		exit(1);

/*
	if (testVectorDHAES(&keypair))
		printf("DHAES works!\n");
	else
		exit(1);
*/

	dlkp_pFree(&keypair);

	if (testVectorRSA())
		printf("RSA works!\n");
	else
		exit(1);
/*
	if (testVectorDLDP())
		printf("dldp with generator of order q works!\n");
	else
		exit(1);
*/

	return 0;
}
#else
int main()
{
	int i, j;

	printf("the beecrypt library implements:\n");
	printf("  %d entropy source%s:\n", entropySourceCount(), entropySourceCount() == 1 ? "" : "s");
	for (i = 0; i < entropySourceCount(); i++)
	{
		const entropySource* tmp = entropySourceGet(i);
		if (tmp)
			printf("    %s\n", tmp->name);
		else
			printf("*** error: library corrupt\n");
	}
	printf("  %d random generator%s:\n", randomGeneratorCount(), randomGeneratorCount() == 1 ? "" : "s");
	for (i = 0; i < randomGeneratorCount(); i++)
	{
		const randomGenerator* tmp = randomGeneratorGet(i);
		if (tmp)
			printf("    %s\n", tmp->name);
		else
			printf("*** error: library corrupt\n");
	}
	printf("  %d hash function%s:\n", hashFunctionCount(), hashFunctionCount() == 1 ? "" : "s");
	for (i = 0; i < hashFunctionCount(); i++)
	{
		const hashFunction* tmp = hashFunctionGet(i);
		if (tmp)
			printf("    %s\n", tmp->name);
		else
			printf("*** error: library corrupt\n");
	}
	printf("  %d keyed hash function%s:\n", keyedHashFunctionCount(), keyedHashFunctionCount() == 1 ? "" : "s");
	for (i = 0; i < keyedHashFunctionCount(); i++)
	{
		const keyedHashFunction* tmp = keyedHashFunctionGet(i);
		if (tmp)
			printf("    %s\n", tmp->name);
		else
			printf("*** error: library corrupt\n");
	}
	printf("  %d blockcipher%s:\n", blockCipherCount(), blockCipherCount() == 1 ? "" : "s");
	for (i = 0; i < blockCipherCount(); i++)
	{
		const blockCipher* tmp = blockCipherGet(i);
		if (tmp)
		{
			printf("    %s ", tmp->name);
			for (j = tmp->keybitsmin; j <= tmp->keybitsmax; j += tmp->keybitsinc)
			{
				printf("%d", j);
				if (j < tmp->keybitsmax)
					printf("/");
				else
					printf(" bit keys\n");
			}
		}
		else
			printf("*** error: library corrupt\n");
	}
	testBlockCiphers();
	testHashFunctions();
	testExpMods();
	testRSA();
	testDLAlgorithms();

	printf("done\n");

	return 0;
}
#endif
