#include <stdio.h>

#include "beecrypt.h"
#include "dldp.h"

int main()
{
	int failures = 0;

	dldp_p params;
	randomGeneratorContext rngc;

        memset(&params, 0, sizeof(dldp_p));

        if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
        {                        
                mp32number gq;

                mp32nzero(&gq);

		/* make parameters with p = 512 bits, q = 160 bits, g of order (q) */
                dldp_pgoqMake(&params, &rngc, 512 >> 5, 160 >> 5, 1);

                /* we have the parameters, now see if g^q == 1 */
                mp32bnpowmod(&params.p, &params.g, (mp32number*) &params.q, &gq);
                if (mp32isone(gq.size, gq.data))
			printf("ok\n");
		else
			failures++;

                mp32nfree(&gq);

                dldp_pFree(&params);

                randomGeneratorContextFree(&rngc);  
        }
	else
		return -1;

	return failures;
}
