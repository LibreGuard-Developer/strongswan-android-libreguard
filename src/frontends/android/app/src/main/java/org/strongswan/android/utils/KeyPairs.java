/*
 * Copyright (C) 2023 Relution GmbH
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

package org.strongswan.android.utils;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.strongswan.android.security.Pkcs12KeyStoreLoader;

public class KeyPairs
{
	@NonNull
	private static KeyStore toKeyStore(@NonNull byte[] bytes, @NonNull char[] password)
		throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException
	{
		final Pkcs12KeyStoreLoader.LoadResult result = Pkcs12KeyStoreLoader.load(bytes, password);
		if (result.isSuccess() && result.getKeyStore() != null)
		{
			return result.getKeyStore();
		}

		final Exception exception = result.getException();
		if (exception instanceof IOException)
		{
			throw (IOException)exception;
		}
		if (exception instanceof KeyStoreException)
		{
			throw (KeyStoreException)exception;
		}
		if (exception instanceof CertificateException)
		{
			throw (CertificateException)exception;
		}
		if (exception instanceof NoSuchAlgorithmException)
		{
			throw (NoSuchAlgorithmException)exception;
		}
		throw new IOException(result.getFailureReason() != null ? result.getFailureReason() : "Unable to load PKCS#12 keystore", exception);
	}

	@Nullable
	private static KeyPair getKeyPair(
		@NonNull final KeyStore keyStore,
		@NonNull final String alias,
		@NonNull final char[] passwordChars)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final Certificate certificate = keyStore.getCertificate(alias);
		if (!(certificate instanceof X509Certificate))
		{
			return null;
		}

		final Key key = keyStore.getKey(alias, passwordChars);
		if (key == null)
		{
			return null;
		}
		return new KeyPair(certificate, (PrivateKey)key);
	}

	@Nullable
	private static KeyPair getKeyPair(@NonNull KeyStore keyStore, @NonNull char[] passwordChars)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements())
		{
			final String alias = aliases.nextElement();
			final KeyPair keyPair = getKeyPair(keyStore, alias, passwordChars);
			if (keyPair != null)
			{
				return keyPair;
			}
		}
		return null;
	}

	@Nullable
	public static KeyPair from(@NonNull final String userCertificate, @NonNull final String password)
		throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final byte[] bytes = android.util.Base64.decode(userCertificate, android.util.Base64.DEFAULT);
		final char[] passwordChars = password.toCharArray();

		final KeyStore keyStore = toKeyStore(bytes, passwordChars);
		return getKeyPair(keyStore, passwordChars);
	}

	private KeyPairs() {}
}
