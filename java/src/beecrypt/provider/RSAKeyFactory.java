package beecrypt.provider;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import beecrypt.beeyond.*;
import beecrypt.io.*;
import beecrypt.security.*;

public final class RSAKeyFactory extends KeyFactorySpi
{
	protected PrivateKey engineGeneratePrivate(KeySpec spec) throws InvalidKeySpecException
	{
		if (spec instanceof RSAPrivateKeySpec)
		{
			if (spec instanceof RSAPrivateCrtKeySpec)
				return new RSAPrivateCrtKeyImpl((RSAPrivateCrtKeySpec) spec);

			return new RSAPrivateKeyImpl((RSAPrivateKeySpec) spec);
		}

		if (spec instanceof EncodedKeySpec)
		{
			EncodedKeySpec enc = (EncodedKeySpec) spec;

			try
			{
				KeyFactory kf = KeyFactory.getInstance(enc.getFormat());
				PrivateKey pri = kf.generatePrivate(enc);
				if (pri instanceof RSAPrivateKey)
					return pri;

				throw new InvalidKeySpecException("Invalid KeySpec encoding format");
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new InvalidKeySpecException("Unsupported KeySpec encoding format");
			}
		}

		throw new InvalidKeySpecException("Unsupported KeySpec type");
	}

	protected PublicKey engineGeneratePublic(KeySpec spec) throws InvalidKeySpecException
	{
		if (spec instanceof RSAPublicKeySpec)
		{
			return new RSAPublicKeyImpl((RSAPublicKeySpec) spec);
		}

		if (spec instanceof EncodedKeySpec)
		{
			EncodedKeySpec enc = (EncodedKeySpec) spec;

			try
			{
				KeyFactory kf = KeyFactory.getInstance(enc.getFormat());
				PublicKey pub = kf.generatePublic(enc);
				if (pub instanceof RSAPublicKey)
					return pub;

				throw new InvalidKeySpecException("Invalid KeySpec encoding format");
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new InvalidKeySpecException("Unsupported KeySpec encoding format");
			}
		}

		throw new InvalidKeySpecException("Unsupported KeySpec type");
	}

	protected KeySpec engineGetKeySpec(Key key, Class keySpec) throws InvalidKeySpecException
	{
		if (key instanceof RSAPublicKey)
		{
			RSAPublicKey pub = (RSAPublicKey) key;

			if (keySpec.equals(KeySpec.class) || keySpec.equals(RSAPublicKeySpec.class))
			{
				return new RSAPublicKeySpec(pub.getModulus(), pub.getPublicExponent());
			}
			if (keySpec.equals(EncodedKeySpec.class))
			{
				String format = pub.getFormat();
				if (format != null)
				{
					byte[] enc = pub.getEncoded();
					if (enc != null)
						return new AnyEncodedKeySpec(format, enc);
				}
			}
		}
		else if (key instanceof RSAPrivateCrtKey)
		{
			RSAPrivateCrtKey pri = (RSAPrivateCrtKey) key;

			if (keySpec.equals(KeySpec.class) || keySpec.equals(RSAPrivateKeySpec.class) || keySpec.equals(RSAPrivateCrtKeySpec.class))
			{
				return new RSAPrivateCrtKeySpec(pri.getModulus(), pri.getPublicExponent(), pri.getPrivateExponent(), pri.getPrimeP(), pri.getPrimeQ(), pri.getPrimeExponentP(), pri.getPrimeExponentQ(), pri.getCrtCoefficient());
			}
			if (keySpec.equals(EncodedKeySpec.class))
			{
				String format = pri.getFormat();
				if (format != null)
				{
					byte[] enc = pri.getEncoded();
					if (enc != null)
						return new AnyEncodedKeySpec(format, enc);
				}
			}
		}
		else if (key instanceof RSAPrivateKey)
		{
			RSAPrivateKey pri = (RSAPrivateKey) key;

			if (keySpec.equals(KeySpec.class) || keySpec.equals(RSAPublicKeySpec.class))
			{
				return new RSAPrivateKeySpec(pri.getModulus(), pri.getPrivateExponent());
			}
			if (keySpec.equals(EncodedKeySpec.class))
			{
				String format = pri.getFormat();
				if (format != null)
				{
					byte[] enc = pri.getEncoded();
					if (enc != null)
						return new AnyEncodedKeySpec(format, enc);
				}
			}
		}
		throw new InvalidKeySpecException("Unsupported Key type");
	}

	protected Key engineTranslateKey(Key key) throws InvalidKeyException
	{
		if (key instanceof RSAPublicKey)
		{
			return new RSAPublicKeyImpl((RSAPublicKey) key);
		}
		else if (key instanceof RSAPrivateCrtKey)
		{
			return new RSAPrivateCrtKeyImpl((RSAPrivateCrtKey) key);
		}
		else if (key instanceof RSAPrivateKey)
		{
			return new RSAPrivateKeyImpl((RSAPrivateKey) key);
		}
		throw new InvalidKeyException("Unsupported Key type");
	}

	public RSAKeyFactory()
	{
	}
}
