#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/api.h"

#if JAVAGLUE

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

#include "beecrypt_tools.h"

jobject mp_to_bigint(JNIEnv* env, size_t size, mpw* data)
{
    jclass cls = (*env)->FindClass(env, "java/math/BigInteger");
    jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "([B)V");
    if (mid)
    {
        size_t sigbits = mpbits(size, data);
        size_t req = (sigbits + 8) >> 3;

        jbyteArray tmp = (*env)->NewByteArray(env, req);
        jbyte* tmpdata = (*env)->GetByteArrayElements(env, tmp, (jboolean*) 0);

        if (tmpdata)
        {
            int rc = i2osp(tmpdata, req, data, size);

            (*env)->ReleaseByteArrayElements(env, tmp, tmpdata, 0);

            return (*env)->NewObject(env, cls, mid, tmp);
        }
    }
}

#endif
