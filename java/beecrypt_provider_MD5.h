/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class beecrypt_provider_MD5 */

#ifndef _Included_beecrypt_provider_MD5
#define _Included_beecrypt_provider_MD5
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     beecrypt_provider_MD5
 * Method:    allocParam
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_provider_MD5_allocParam
  (JNIEnv *, jclass);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    cloneParam
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_provider_MD5_cloneParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    freeParam
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_beecrypt_provider_MD5_freeParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    digest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_beecrypt_provider_MD5_digest__J
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    digest
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_beecrypt_provider_MD5_digest__J_3BII
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_beecrypt_provider_MD5_reset
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_beecrypt_provider_MD5_update__JB
  (JNIEnv *, jclass, jlong, jbyte);

/*
 * Class:     beecrypt_provider_MD5
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_provider_MD5_update__J_3BII
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
