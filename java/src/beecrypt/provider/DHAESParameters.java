package beecrypt.provider;

import java.io.*;
import java.security.*;
import java.security.spec.*;

import beecrypt.crypto.spec.*;

public class DHAESParameters extends AlgorithmParametersSpi
{
	private DHAESParameterSpec spec = null;
	private DHAESDecryptParameterSpec dspec = null;

	protected byte[] engineGetEncoded() throws IOException
	{
		throw new IOException("not implemented");
	}

	protected byte[] engineGetEncoded(String format) throws IOException
	{
		throw new IOException("not implemented");
	}

	protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException
	{
		if (paramSpec.isAssignableFrom(DHAESDecryptParameterSpec.class))
		{
			if (dspec != null)
				return dspec;
		}
		else if (paramSpec.isAssignableFrom(DHAESDecryptParameterSpec.class) || paramSpec.isAssignableFrom(AlgorithmParameterSpec.class))
		{
			if (spec != null)
				return spec;
		}
		throw new InvalidParameterSpecException();
	}

	protected void engineInit(AlgorithmParameterSpec param) throws InvalidParameterSpecException
	{
		spec = null;
		dspec = null;

		if (param instanceof DHAESParameterSpec)
		{
			spec = (DHAESParameterSpec) spec;
			if (spec instanceof DHAESDecryptParameterSpec)
				dspec = (DHAESDecryptParameterSpec) spec;
		}
		else
			throw new InvalidParameterSpecException("Expected a DHAESParameterSpec");
	}

	protected void engineInit(byte[] params)
	{
		throw new ProviderException("not implemented");
	}

	protected void engineInit(byte[] params, String format)
	{
		throw new ProviderException("not implemented");
	}

	protected String engineToString()
	{
		if (dspec != null)
			return dspec.toString();
		if (spec != null)
			return spec.toString();
		return "(uninitialized)";
	}
}
