package beecrypt.provider;

import java.security.*;

/**
 * This class specifies the set of algorithms defined by the
 * BeeCrypt JCE 1.4 Cryptography Provider.
 * <p>
 * @author Bob Deblier &lt;bob.deblier@telenet.be&gt;
 */
public final class BaseProvider extends Provider
{
	private static final String
		NAME = "BeeCrypt",
		INFO = "BeeCrypt JCE 1.4 Cryptography Provider";

	private static final double
		VERSION = 4.2;

	static
	{
		System.loadLibrary("beecrypt");
		System.loadLibrary("beecrypt_java");
	}

	public BaseProvider()
	{
		super(NAME, VERSION, INFO);
		
		AccessController.doPrivileged(new java.security.PrivilegedAction()
			{
				public Object run()
				{
					setProperty("AlgorithmParameters.DH", "beecrypt.provider.DHParameters");
					setProperty("AlgorithmParameters.DHAES", "beecrypt.provider.DHAESParameters");
					setProperty("AlgorithmParameters.DSA", "beecrypt.provider.DSAParameters");
					setProperty("CertificateFactory.BEE", "beecrypt.provider.BeeCertificateFactory");
					setProperty("CertPathValidator.BEE", "beecrypt.provider.BeeCertPathValidator");
					setProperty("KeyFactory.DH", "beecrypt.provider.DHKeyFactory");
					setProperty("KeyFactory.DSA", "beecrypt.provider.DSAKeyFactory");
					setProperty("KeyFactory.RSA", "beecrypt.provider.RSAKeyFactory");
					setProperty("KeyPairGenerator.RSA", "beecrypt.provider.RSAKeyPairGenerator");
					setProperty("KeyStore.BEE", "beecrypt.provider.BeeKeyStore");
					setProperty("MessageDigest.MD5", "beecrypt.provider.MD5");
					setProperty("MessageDigest.SHA-1", "beecrypt.provider.SHA1");
					setProperty("MessageDigest.SHA-256", "beecrypt.provider.SHA256");
					setProperty("MessageDigest.SHA-384", "beecrypt.provider.SHA384");
					setProperty("MessageDigest.SHA-512", "beecrypt.provider.SHA512");
					setProperty("Als.Alias.KeyFactory.DiffieHellman", "KeyFactory.DH");
					setProperty("Als.Alias.MessageDigest.SHA", "MessageDigest.SHA-1");

					return null;
				}
			}
		);
	}
}
