/*
 * Copyright (c) 1999, 2000, 2001, 2002 Virtual Unlimited B.V.
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

/*!\file beecrypt.h
 * \brief BeeCrypt API, headers.
 *
 * These API functions provide an abstract way for using most of
 * the various algorithms implemented by the library.
 *
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup ES_m PRNG_m HASH_m HMAC_m BC_m
 */

#ifndef _BEECRYPT_H
#define _BEECRYPT_H

#include "beecrypt.api.h"

#include "memchunk.h"
#include "mpnumber.h"

/*
 * Entropy Sources
 */

/*!\typedef entropyNext
 * \brief Prototype definition for an entropy-generating function.
 * \ingroup ES_m
 */
typedef int (*entropyNext)(byte*, size_t);

/*
 * The struct 'entropySource' holds information and pointers to code specific
 * to each entropy source. Each specific entropy source MUST be written to be
 * multithread-safe.
 *
 * The struct contains the following function(s):
 *
 * int (*next)(uint32_t* data, int size);
 *
 * This function will fill an array of 32-bit unsigned integers of given size
 * with entropy.
 * Return value is 0 on success, or -1 on failure.
 */

/*!\brief This struct holds information and pointers to code specific to each source of entropy.
 * \ingroup ES_m
 */
typedef struct
{
	/*!\var name
	 * \brief The entropy source's name.
	 */
	const char*			name;
	/*!\var next
	 */
	const entropyNext	next;
} entropySource;

/*
 * You can use the following functions to find entropy sources implemented by
 * the library:
 *
 * entropySourceCount returns the number of sources available.
 *
 * entropySourceGet returns the entropy source with a given index (starting
 * at zero, up to entropySourceCount() - 1), or NULL if the index was out of
 * bounds.
 *
 * entropySourceFind returns the entropy source with the given name, or NULL
 * if no entropy source exists with that name.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int						entropySourceCount();
BEECRYPTAPI
const entropySource*	entropySourceGet(int);
BEECRYPTAPI
const entropySource*	entropySourceFind(const char*);
BEECRYPTAPI
const entropySource*	entropySourceDefault();

/*
 * The following function can try multiple entropy sources for gathering
 * the requested amount. It will only try multiple sources if variable
 * BEECRYPT_ENTROPY is not set.
 */

BEECRYPTAPI
int						entropyGatherNext(byte*, size_t);

#ifdef __cplusplus
}
#endif

/*
 * Pseudo-random Number Generators
 */

typedef void randomGeneratorParam;

typedef int (*randomGeneratorSetup  )(randomGeneratorParam*);
typedef int (*randomGeneratorSeed   )(randomGeneratorParam*, const byte*, size_t);
typedef int (*randomGeneratorNext   )(randomGeneratorParam*, byte*, size_t);
typedef int (*randomGeneratorCleanup)(randomGeneratorParam*);

/*
 * The struct 'randomGenerator' holds information and pointers to code specific
 * to each random generator. Each specific random generator MUST be written to
 * be multithread safe.
 *
 * WARNING: each randomGenerator, when used in cryptographic applications, MUST
 * be guaranteed to be of suitable quality and strength (i.e. don't use the
 * random() function found in most UN*X-es).
 *
 * Multiple instances of each randomGenerator can be used (even concurrently),
 * provided they each use their own randomGeneratorParam parameters, a chunk
 * of memory which must be at least as large as indicated by the paramsize
 * field.
 *
 */

typedef struct
{
	const char*						name;
	const unsigned int				paramsize;
	const randomGeneratorSetup		setup;
	const randomGeneratorSeed		seed;
	const randomGeneratorNext		next;
	const randomGeneratorCleanup	cleanup;
} randomGenerator;

/*
 * You can use the following functions to find random generators implemented by
 * the library:
 *
 * randomGeneratorCount returns the number of generators available.
 *
 * randomGeneratorGet returns the random generator with a given index (starting
 * at zero, up to randomGeneratorCount() - 1), or NULL if the index was out of
 * bounds.
 *
 * randomGeneratorFind returns the random generator with the given name, or
 * NULL if no random generator exists with that name.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int						randomGeneratorCount();
BEECRYPTAPI
const randomGenerator*	randomGeneratorGet(int);
BEECRYPTAPI
const randomGenerator*	randomGeneratorFind(const char*);
BEECRYPTAPI
const randomGenerator*	randomGeneratorDefault();

#ifdef __cplusplus
}
#endif

/*
 * The struct 'randomGeneratorContext' is used to contain both the functional
 * part (the randomGenerator), and its parameters.
 */

typedef struct
{
	const randomGenerator* rng;
	randomGeneratorParam* param;
} randomGeneratorContext;

/*
 * The following functions can be used to initialize and free a
 * randomGeneratorContext. Initializing will allocate a buffer of the size
 * required by the randomGenerator, freeing will deallocate that buffer.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int randomGeneratorContextInit(randomGeneratorContext*, const randomGenerator*);
BEECRYPTAPI
int randomGeneratorContextFree(randomGeneratorContext*);
BEECRYPTAPI
int randomGeneratorContextNext(randomGeneratorContext*, byte*, size_t);

#ifdef __cplusplus
}
#endif

/*
 * Hash Functions
 */

/*!typedef void hashFunctionParam
 * \ingroup HASH_m
 */
typedef void hashFunctionParam;

typedef int (*hashFunctionReset )(hashFunctionParam*);
typedef int (*hashFunctionUpdate)(hashFunctionParam*, const byte*, size_t);
typedef int (*hashFunctionDigest)(hashFunctionParam*, byte*);

/*
 * The struct 'hashFunction' holds information and pointers to code specific
 * to each hash function. Specific hash functions MAY be written to be
 * multithread-safe.
 *
 * NOTE: data MUST have a size (in bytes) of at least 'digestsize' as described
 * in the hashFunction struct.
 * NOTE: for safety reasons, after calling digest, each specific implementation
 * MUST reset itself so that previous values in the parameters are erased.
 */

typedef struct
{
	const char*					name;
	const unsigned int			paramsize;	/* in bytes */
	const unsigned int			blocksize;	/* in bytes */
	const unsigned int			digestsize;	/* in bytes */
	const hashFunctionReset		reset;
	const hashFunctionUpdate	update;
	const hashFunctionDigest	digest;
} hashFunction;

/*
 * You can use the following functions to find hash functions implemented by
 * the library:
 *
 * hashFunctionCount returns the number of hash functions available.
 *
 * hashFunctionGet returns the hash function with a given index (starting
 * at zero, up to hashFunctionCount() - 1), or NULL if the index was out of
 * bounds.
 *
 * hashFunctionFind returns the hash function with the given name, or
 * NULL if no hash function exists with that name.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int					hashFunctionCount();
BEECRYPTAPI
const hashFunction*	hashFunctionGet(int);
BEECRYPTAPI
const hashFunction*	hashFunctionFind(const char*);
BEECRYPTAPI
const hashFunction*	hashFunctionDefault();

#ifdef __cplusplus
}
#endif

/*
 * The struct 'hashFunctionContext' is used to contain both the functional
 * part (the hashFunction), and its parameters.
 */

typedef struct
{
	const hashFunction* algo;
	hashFunctionParam* param;
} hashFunctionContext;

/*
 * The following functions can be used to initialize and free a
 * hashFunctionContext. Initializing will allocate a buffer of the size
 * required by the hashFunction, freeing will deallocate that buffer.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int hashFunctionContextInit(hashFunctionContext*, const hashFunction*);
BEECRYPTAPI
int hashFunctionContextFree(hashFunctionContext*);
BEECRYPTAPI
int hashFunctionContextReset(hashFunctionContext*);
BEECRYPTAPI
int hashFunctionContextUpdate(hashFunctionContext*, const byte*, size_t);
BEECRYPTAPI
int hashFunctionContextUpdateMC(hashFunctionContext*, const memchunk*);
BEECRYPTAPI
int hashFunctionContextUpdateMP(hashFunctionContext*, const mpnumber*);
BEECRYPTAPI
int hashFunctionContextDigest(hashFunctionContext*, byte*);
BEECRYPTAPI
int hashFunctionContextDigestMP(hashFunctionContext*, mpnumber*);
BEECRYPTAPI
int hashFunctionContextDigestMatch(hashFunctionContext*, const mpnumber*);

#ifdef __cplusplus
}
#endif

/*
 * Keyed Hash Functions, a.k.a. Message Authentication Codes
 */

/*!\typedef void keyedHashFunctionParam
 * \ingroup HMAC_m
 */
typedef void keyedHashFunctionParam;

typedef int (*keyedHashFunctionSetup  )(keyedHashFunctionParam*, const byte*, size_t);
typedef int (*keyedHashFunctionReset  )(keyedHashFunctionParam*);
typedef int (*keyedHashFunctionUpdate )(keyedHashFunctionParam*, const byte*, size_t);
typedef int (*keyedHashFunctionDigest )(keyedHashFunctionParam*, byte*);

/*
 * The struct 'keyedHashFunction' holds information and pointers to code
 * specific to each keyed hash function. Specific keyed hash functions MAY be
 * written to be multithread-safe.
 *
 * The struct field 'keybitsmin' contains the minimum number of bits a key
 * must contains, 'keybitsmax' the maximum number of bits a key may contain,
 * 'keybitsinc', the increment in bits that may be used between min and max.
 * 
 * NOTE: data must be at least have a bytesize of 'digestsize' as described
 * in the keyedHashFunction struct.
 * NOTE: for safety reasons, after calling digest, each specific implementation
 * MUST reset itself so that previous values in the parameters are erased.
 */

typedef struct
{
	const char*						name;
	const unsigned int				paramsize;	/* in bytes */
	const unsigned int				blocksize;	/* in bytes */
	const unsigned int				digestsize;	/* in bytes */
	const unsigned int				keybitsmin;	/* in bits */
	const unsigned int				keybitsmax;	/* in bits */
	const unsigned int				keybitsinc;	/* in bits */
	const keyedHashFunctionSetup	setup;
	const keyedHashFunctionReset	reset;
	const keyedHashFunctionUpdate	update;
	const keyedHashFunctionDigest	digest;
} keyedHashFunction;

/*
 * You can use the following functions to find keyed hash functions implemented
 * by the library:
 *
 * keyedHashFunctionCount returns the number of keyed hash functions available.
 *
 * keyedHashFunctionGet returns the keyed hash function with a given index
 * (starting at zero, up to keyedHashFunctionCount() - 1), or NULL if the index
 * was out of bounds.
 *
 * keyedHashFunctionFind returns the keyed hash function with the given name,
 * or NULL if no keyed hash function exists with that name.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int							keyedHashFunctionCount();
BEECRYPTAPI
const keyedHashFunction*	keyedHashFunctionGet(int);
BEECRYPTAPI
const keyedHashFunction*	keyedHashFunctionFind(const char*);
BEECRYPTAPI
const keyedHashFunction*	keyedHashFunctionDefault();

#ifdef __cplusplus
}
#endif

/*
 * The struct 'keyedHashFunctionContext' is used to contain both the functional
 * part (the keyedHashFunction), and its parameters.
 */

typedef struct
{
	const keyedHashFunction*	algo;
	keyedHashFunctionParam*		param;
} keyedHashFunctionContext;

/*
 * The following functions can be used to initialize and free a
 * keyedHashFunctionContext. Initializing will allocate a buffer of the size
 * required by the keyedHashFunction, freeing will deallocate that buffer.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int keyedHashFunctionContextInit(keyedHashFunctionContext*, const keyedHashFunction*);
BEECRYPTAPI
int keyedHashFunctionContextFree(keyedHashFunctionContext*);
BEECRYPTAPI
int keyedHashFunctionContextSetup(keyedHashFunctionContext*, const byte*, size_t);
BEECRYPTAPI
int keyedHashFunctionContextReset(keyedHashFunctionContext*);
BEECRYPTAPI
int keyedHashFunctionContextUpdate(keyedHashFunctionContext*, const byte*, size_t);
BEECRYPTAPI
int keyedHashFunctionContextUpdateMC(keyedHashFunctionContext*, const memchunk*);
BEECRYPTAPI
int keyedHashFunctionContextUpdateMP(keyedHashFunctionContext*, const mpnumber*);
BEECRYPTAPI
int keyedHashFunctionContextDigest(keyedHashFunctionContext*, byte*);
BEECRYPTAPI
int keyedHashFunctionContextDigestMP(keyedHashFunctionContext*, mpnumber*);
BEECRYPTAPI
int keyedHashFunctionContextDigestMatch(keyedHashFunctionContext*, const mpnumber*);

#ifdef __cplusplus
}
#endif

/*
 * Block ciphers
 */

/*!\enum cipherOperation
 * \brief Specifies whether to perform encryption or decryption.
 * \ingroup BC_m
 */
typedef enum
{
	ENCRYPT,
	DECRYPT
} cipherOperation;

/*!\typedef void blockCipherParam
 * \brief Placeholder type definition for blockcipher parameters.
 * \sa aesParam, blowfishParam.
 * \ingroup BC_m
 */
typedef void blockCipherParam;

/*!\brief Prototype definition for a setup function.
 * \ingroup BC_m
 */
typedef int (*blockCipherSetup  )(blockCipherParam*, const byte*, size_t, cipherOperation);

/*!\typedef int (*blockCipherSetIV)(blockCipherPatam* bp, const byte* iv)
 * \brief Prototype definition for an initialization vector setup function.
 * \param bp The blockcipher's parameters.
 * \param iv The blockciphers' IV value.
 * \note iv length must be equal to the cipher's block size.
 * \retval 0 on success.
 * \retval -1 on failure.
 * \ingroup BC_m
 */
typedef int (*blockCipherSetIV  )(blockCipherParam*, const byte*);

/*!\typedef int (*blockCipherEncrypt)(blockCipherParam* bp, uint32_t* dst, const uint32_t* src)
 * \brief Prototype for a \e raw encryption function.
 * \param bp The blockcipher's parameters.
 * \param dst The destination address.
 * \param sec The source address.
 * \note This is a raw encryption function.
 * \note Type uint32_t* is used for dst and src to indicate that memory should be aligned on a 4-byte boundary.
 * \retval 0 on success.
 * \retval -1 on failure.
 * \ingroup BC_m
 */
typedef int (*blockCipherEncrypt)(blockCipherParam*, uint32_t*, const uint32_t*);

/*!\typedef blockCipherDecrypt
 * \brief Prototype definition for a \e raw decryption function.
 * \ingroup BC_m
 */
typedef int (*blockCipherDecrypt)(blockCipherParam*, uint32_t*, const uint32_t*);

typedef uint32_t* (*blockCipherFeedback)(blockCipherParam*);

/*!\brief Holds information and pointers to code specific to each cipher.
 *
 * Specific block ciphers \e may be written to be multithread-safe.
 *
 * \ingroup BC_m
 */
typedef struct
{
	/*!\var name
	 * \brief The blockcipher's name.
	 */
	const char*					name;
	/*!\var paramsize
	 * \brief The size of the parameters required by this cipher, in bytes.
	 */
	const unsigned int			paramsize;
	/*!\var blocksize
	 * \brief The size of one block of data, in bytes.
	 */
	const unsigned int			blocksize;
	/*!\var keybitsmin
	 * \brief The minimum number of key bits.
	 */
	const unsigned int			keybitsmin;
	/*!\var keybitsmax
	 * \brief The maximum number of key bits.
	 */
	const unsigned int			keybitsmax;
	/*!\var keybitsinc
	 * \brief The allowed increment in key bits between min and max.
	 * \see keybitsmin and keybitsmax.
	 */
	const unsigned int			keybitsinc;
	/*!\var setup
	 * \brief Pointer to the cipher's setup function.
	 */
	const blockCipherSetup		setup;
	/*!\var setiv
	 * \brief Pointer to the cipher's initialization vector setup function.
	 */
	const blockCipherSetIV		setiv;
	/*!\var encrypt
	 * \brief Pointer to the cipher's encryption function.
	 */
	const blockCipherEncrypt	encrypt;
	/*!\var decrypt
	 * \brief Pointer to the cipher's decryption function.
	 */
	const blockCipherDecrypt	decrypt;
	/*!\var getfb
	 * \brief Pointer to the cipher's feedback-returning function.
	 */
	const blockCipherFeedback   getfb;
} blockCipher;

/*
 * You can use the following functions to find blockciphers implemented by
 * the library:
 *
 * blockCipherCount returns the number of blockciphers available.
 *
 * blockCipherGet returns the blockcipher with a given index (starting
 * at zero, up to blockCipherCount() - 1), or NULL if the index was out of
 * bounds.
 *
 * blockCipherFind returns the blockcipher with the given name, or
 * NULL if no hash function exists with that name.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int						blockCipherCount();
BEECRYPTAPI
const blockCipher*		blockCipherGet(int);
BEECRYPTAPI
const blockCipher*		blockCipherFind(const char*);
BEECRYPTAPI
const blockCipher*		blockCipherDefault();

#ifdef __cplusplus
}
#endif

/*
 * The struct 'blockCipherContext' is used to contain both the functional
 * part (the blockCipher), and its parameters.
 */
/*!\brief Holds a pointer to a blockcipher as well as its parameters.
 * \warning A context can be used by only one thread at the same time.
 * \ingroup BC_m
 */
typedef struct
{
	/*!\var algo
	 * \brief Pointer to a blockCipher.
	 */
	const blockCipher* algo;
	/*!\var param
	 * \brief Pointer to the parameters used by algo.
	 */
	blockCipherParam* param;
} blockCipherContext;

/*
 * The following functions can be used to initialize and free a
 * blockCipherContext. Initializing will allocate a buffer of the size
 * required by the blockCipher, freeing will deallocate that buffer.
 */

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int blockCipherContextInit(blockCipherContext*, const blockCipher*);

BEECRYPTAPI
int blockCipherContextSetup(blockCipherContext*, const byte*, size_t, cipherOperation);

BEECRYPTAPI
int blockCipherContextSetIV(blockCipherContext*, const byte*);

BEECRYPTAPI
int blockCipherContextFree(blockCipherContext*);

#ifdef __cplusplus
}
#endif

#endif
