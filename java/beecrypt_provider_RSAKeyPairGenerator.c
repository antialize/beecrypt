#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/rsakp.h"

#if JAVAGLUE

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

#include "beecrypt_tools.h"
#include "beecrypt_provider_RSAKeyPairGenerator.h"

/* need an adapter from SecureRandom to randomGenerator */

void JNICALL Java_beecrypt_provider_RSAKeyPairGenerator_generate(JNIEnv* env, jobject obj)
{
	jclass cls = (*env)->GetObjectClass(env, obj);
	jfieldID sid = (*env)->GetFieldID(env, cls, "_size", "I");
	jfieldID fid; // = (*env)->GetFieldID(env, cls, "_e", "Ljava/math/BigInteger;");
	if (sid)
	{
		randomGeneratorContext rngc;
		rsakp pair;
		jint keybits = (*env)->GetIntField(env, obj, sid);

		if (keybits < 768)
			keybits = 768;

		randomGeneratorContextInit(&rngc, randomGeneratorDefault());

		rsakpInit(&pair);

		/*!\todo transform field _e to pair.e */

		rsakpMake(&pair, &rngc, (size_t) keybits);

		if ((fid = (*env)->GetFieldID(env, cls, "_n", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.n.size, pair.n.modl));

		if ((fid = (*env)->GetFieldID(env, cls, "_e", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.e.size, pair.e.data));

		if ((fid = (*env)->GetFieldID(env, cls, "_d", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.d.size, pair.d.data));

		if ((fid = (*env)->GetFieldID(env, cls, "_p", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.p.size, pair.p.modl));

		if ((fid = (*env)->GetFieldID(env, cls, "_q", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.q.size, pair.q.modl));

		if ((fid = (*env)->GetFieldID(env, cls, "_dp", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.dp.size, pair.dp.data));

		if ((fid = (*env)->GetFieldID(env, cls, "_dq", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.dq.size, pair.dq.data));

		if ((fid = (*env)->GetFieldID(env, cls, "_qi", "Ljava/math/BigInteger;")))
			(*env)->SetObjectField(env, obj, fid, mp_to_bigint(env, pair.qi.size, pair.qi.data));

		rsakpFree(&pair);
		randomGeneratorContextFree(&rngc);
	}
}

#endif
