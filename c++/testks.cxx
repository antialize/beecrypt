#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/io/FileInputStream.h"
using beecrypt::io::FileInputStream;
#include "beecrypt/c++/io/FileOutputStream.h"
using beecrypt::io::FileOutputStream;
#include "beecrypt/c++/security/KeyStore.h"
using beecrypt::security::KeyStore;
#include "beecrypt/c++/security/KeyPairGenerator.h"
using beecrypt::security::KeyPairGenerator;
#include "beecrypt/c++/beeyond/BeeCertificate.h"
using beecrypt::beeyond::BeeCertificate;

#include <iostream>
using std::cout;
using std::endl;
#include <unicode/ustream.h>

int main(int argc, char* argv[])
{
	try
	{
		array<javachar> password(4);

		password[0] = (javachar) 't';
		password[1] = (javachar) 'e';
		password[2] = (javachar) 's';
		password[3] = (javachar) 't';

		KeyStore* ks = KeyStore::getInstance(KeyStore::getDefaultType());

		if (argc == 2)
		{
			FileInputStream fin(fopen(argv[1], "rb"));

			ks->load(&fin, &password);

			Key* k = ks->getKey("rsa", password);

			cout << "k algorithm = " << k->getAlgorithm() << endl;

			delete k;
		}
		else
		{
			KeyPairGenerator* kpg = KeyPairGenerator::getInstance("RSA");

			kpg->initialize(1024);

			KeyPair* pair = kpg->generateKeyPair();

			vector<Certificate*> chain;

			chain.push_back(BeeCertificate::self(pair->getPublic(), pair->getPrivate(), "SHA1withRSA"));

			FileOutputStream fos(fopen("keystore", "wb"));

			// create an empty stream
			ks->load((InputStream*) 0, &password);
			ks->setKeyEntry("rsa", pair->getPrivate(), password, chain);
			ks->store(fos, &password);
		}

		delete ks;
	}
	catch (Exception e)
	{
		cout << "Exception: " + e.getMessage() << endl;
	}
}
