package beecrypt.provider;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import beecrypt.beeyond.*;
import beecrypt.crypto.*;
import beecrypt.io.*;

public final class DHKeyFactory extends KeyFactorySpi
{
	private DHPrivateKey generatePrivate(byte[] enc) throws InvalidKeySpecException
	{
		try
		{
			ByteArrayInputStream bis = new ByteArrayInputStream(enc);
			BeeInputStream bee = new BeeInputStream(bis);

			BigInteger p, g, x;

			p = bee.readBigInteger();
			g = bee.readBigInteger();
			x = bee.readBigInteger();

			return new DHPrivateKeyImpl(p, g, x);
		}
		catch (IOException e)
		{
			throw new InvalidKeySpecException("Invalid KeySpec encoding");
		}
	}

	private DHPublicKey generatePublic(byte[] enc) throws InvalidKeySpecException
	{
		try
		{
			ByteArrayInputStream bis = new ByteArrayInputStream(enc);
			BeeInputStream bee = new BeeInputStream(bis);

			BigInteger p, g, y;

			p = bee.readBigInteger();
			g = bee.readBigInteger();
			y = bee.readBigInteger();

			return new DHPublicKeyImpl(p, g, y);
		}
		catch (IOException e)
		{
			throw new InvalidKeySpecException("Invalid KeySpec encoding");
		}
	}

	protected PrivateKey engineGeneratePrivate(KeySpec spec) throws InvalidKeySpecException
	{
		if (spec instanceof DHPrivateKeySpec)
		{
			return new DHPrivateKeyImpl((DHPrivateKeySpec) spec);
		}

		if (spec instanceof EncodedKeySpec)
		{
			EncodedKeySpec enc = (EncodedKeySpec) spec;

			if (enc.getFormat().equals("BEE"))
			{
				return generatePrivate(enc.getEncoded());
			}
			throw new InvalidKeySpecException("Unsupported KeySpec format");
		}

		throw new InvalidKeySpecException("Unsupported KeySpec type");
	}

	protected PublicKey engineGeneratePublic(KeySpec spec) throws InvalidKeySpecException
	{
		if (spec instanceof DHPublicKeySpec)
		{
			return new DHPublicKeyImpl((DHPublicKeySpec) spec);
		}

		if (spec instanceof EncodedKeySpec)
		{
			EncodedKeySpec enc = (EncodedKeySpec) spec;

			if (enc.getFormat().equals("BEE"))
			{
				return generatePublic(enc.getEncoded());
			}
			throw new InvalidKeySpecException("Unsupported KeySpec format");
		}

		throw new InvalidKeySpecException("Unsupported KeySpec type");
	}

	protected KeySpec engineGetKeySpec(Key key, Class keySpec) throws InvalidKeySpecException
	{
		if (key instanceof DHPublicKey)
		{
			DHPublicKey pub = (DHPublicKey) key;

			if (keySpec.equals(KeySpec.class) || keySpec.equals(DHPublicKeySpec.class))
			{
				return new DHPublicKeySpec(pub.getY(), pub.getParams().getP(), pub.getParams().getG());
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
		else if (key instanceof DHPrivateKey)
		{
			DHPrivateKey pri = (DHPrivateKey) key;

			if (keySpec.equals(KeySpec.class) || keySpec.equals(DHPrivateKeySpec.class))
			{
				return new DHPrivateKeySpec(pri.getX(), pri.getParams().getP(), pri.getParams().getG());
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
		if (key instanceof DHPublicKey)
		{
			return new DHPublicKeyImpl((DHPublicKey) key);
		}
		else if (key instanceof DHPrivateKey)
		{
			return new DHPrivateKeyImpl((DHPrivateKey) key);
		}
		throw new InvalidKeyException("Unsupported Key type");
	}

	public DHKeyFactory()
	{
	}
}
