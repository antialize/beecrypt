#include <stdio.h>

#include "beecrypt.h"
#include "mp.h"

#define INIT	0xdeadbeefU;

static const mpw Z[4] = { 0U, 0U, 0U, 0U };
static const mpw F[4] = { ~((mpw) 0U), ~((mpw) 0U), ~((mpw) 0U), ~((mpw) 0U)};
static const mpw P[8] = { ~((mpw) 0U), ~((mpw) 0U), ~((mpw) 0U), ~((mpw) 0U) - 1U, 0U, 0U, 0U, 1U };

int main()
{
	int i;
	mpw x[4];
	mpw y[4];
	mpw r[8];

	for (i = 0; i < 4; i++)
		x[i] = INIT;

	mpcopy(4, x, Z);
	for (i = 0; i < 4; i++)
	{
		if (x[i] != 0)
		{
			printf("mpcopy failed\n");
			return 1;
		}
	}

	if (!mpeq(4, x, Z))
	{
		printf("mpeq failed\n");
		return 1;
	}
	if (mpne(4, x, Z))
	{
		printf("mpne failed\n");
		return 1;
	}

	mpcopy(4, x, F);
	for (i = 0; i < 4; i++)
	{
		if (x[i] != ~((mpw) 0))
		{
			printf("mpcopy failed\n");
			return 1;
		}
	}

	if (!mpz(4, Z) || mpz(4, F))
	{
		printf("mpz failed\n");
		return 1;
	}
	if (mpnz(4, Z) || !mpnz(4, F))
	{
		printf("mpnz failed\n");
		return 1;
	}

	if (!mpeq(4, x, F))
	{
		printf("mpeq failed\n");
		return 1;
	}
	if (mpne(4, x, F))
	{
		printf("mpne failed\n");
		return 1;
	}

	mpzero(8, r);
	mpmul(r, 4, F, 4, F);
	if (!mpeq(8, r, P))
	{
		printf("mpmul failed\n");
		return 1;
	}

	mpzero(8, r);
	mpsqr(r, 4, F);
	if (!mpeq(8, r, P))
	{
		printf("mpsqr failed\n");
		return 1;
	}

	printf("success\n");

	return 0;
}
