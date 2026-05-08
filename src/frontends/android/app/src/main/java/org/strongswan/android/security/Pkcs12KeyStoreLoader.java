package org.strongswan.android.security;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class Pkcs12KeyStoreLoader
{
	private static final String TAG = "Pkcs12Loader";
	private static final String KEYSTORE_INSTANCE = "PKCS12";
	private static final String BC_PROVIDER = "BC";

	public static final class LoadResult
	{
		private final KeyStore keyStore;
		private final String strategy;
		private final Exception exception;
		private final boolean providerCompatibilityFailure;
		private final String failureReason;

		private LoadResult(
			@Nullable final KeyStore keyStore,
			@Nullable final String strategy,
			@Nullable final Exception exception,
			final boolean providerCompatibilityFailure,
			@Nullable final String failureReason)
		{
			this.keyStore = keyStore;
			this.strategy = strategy;
			this.exception = exception;
			this.providerCompatibilityFailure = providerCompatibilityFailure;
			this.failureReason = failureReason;
		}

		@NonNull
		public static LoadResult success(@NonNull final KeyStore keyStore, @NonNull final String strategy)
		{
			return new LoadResult(keyStore, strategy, null, false, null);
		}

		@NonNull
		public static LoadResult failure(
			@Nullable final String strategy,
			@Nullable final Exception exception,
			final boolean providerCompatibilityFailure,
			@Nullable final String failureReason)
		{
			return new LoadResult(null, strategy, exception, providerCompatibilityFailure, failureReason);
		}

		public boolean isSuccess()
		{
			return keyStore != null;
		}

		@Nullable
		public KeyStore getKeyStore()
		{
			return keyStore;
		}

		@Nullable
		public String getStrategy()
		{
			return strategy;
		}

		@Nullable
		public Exception getException()
		{
			return exception;
		}

		public boolean isProviderCompatibilityFailure()
		{
			return providerCompatibilityFailure;
		}

		@Nullable
		public String getFailureReason()
		{
			return failureReason;
		}
	}

	@NonNull
	public static LoadResult load(@NonNull final byte[] bytes, @Nullable final char[] password)
	{
		final char[] requestedPassword = password != null ? password.clone() : new char[0];
		Exception firstException = null;
		LoadResult compatibilityFailure = null;

		for (Attempt attempt : buildAttempts(requestedPassword))
		{
			try
			{
				final KeyStore keyStore = attempt.load(bytes);
				final String providerName = keyStore.getProvider() != null ? keyStore.getProvider().getName() : "unknown";
				return LoadResult.success(keyStore, attempt.describe(providerName));
			}
			catch (Exception e)
			{
				if (firstException == null)
				{
					firstException = e;
				}
				final boolean compatibilityIssue = looksLikeProviderCompatibilityIssue(e);
				final String failureReason = attempt.describeFailure(e);
				if (compatibilityIssue && compatibilityFailure == null)
				{
					compatibilityFailure = LoadResult.failure(attempt.label, e, true, failureReason);
				}
			}
		}

		if (compatibilityFailure != null)
		{
			return compatibilityFailure;
		}
		return LoadResult.failure(
			"pkcs12-load-failed",
			firstException != null ? firstException : new IOException("Unable to load PKCS#12 keystore"),
			false,
			"Unable to load PKCS#12 keystore with the available providers"
		);
	}

	static boolean looksLikeProviderCompatibilityIssue(@Nullable Throwable throwable)
	{
		while (throwable != null)
		{
			final String message = throwable.getMessage();
			if (message != null)
			{
				final String normalized = message.toLowerCase(Locale.US);
				if (normalized.contains("no installed provider supports this key") ||
					normalized.contains("pkcs12key") ||
					normalized.contains("error constructing mac"))
				{
					return true;
				}
			}
			throwable = throwable.getCause();
		}
		return false;
	}

	@NonNull
	private static List<Attempt> buildAttempts(@NonNull final char[] requestedPassword)
	{
		final List<char[]> passwords = buildPasswordCandidates(requestedPassword);
		final List<Attempt> attempts = new ArrayList<>();
		for (char[] password : passwords)
		{
			attempts.add(new Attempt("default-provider", password, false));
		}
		for (char[] password : passwords)
		{
			attempts.add(new Attempt("bc-priority", password, true));
		}
		return attempts;
	}

	@NonNull
	private static List<char[]> buildPasswordCandidates(@NonNull final char[] requestedPassword)
	{
		final ArrayList<char[]> candidates = new ArrayList<>();
		candidates.add(requestedPassword.clone());
		if (!Arrays.equals(requestedPassword, new char[0]))
		{
			candidates.add(new char[0]);
		}
		return candidates;
	}

	@Nullable
	private static Integer getProviderPosition(@NonNull final String providerName)
	{
		final Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++)
		{
			if (providerName.equals(providers[i].getName()))
			{
				return i + 1;
			}
		}
		return null;
	}

	@NonNull
	private static KeyStore loadKeyStore(@NonNull final byte[] bytes, @NonNull final char[] password, final boolean prioritizeBc)
		throws Exception
	{
		synchronized (Pkcs12KeyStoreLoader.class)
		{
			final Provider bcProvider = Security.getProvider(BC_PROVIDER);
			final Integer originalBcPosition = prioritizeBc ? getProviderPosition(BC_PROVIDER) : null;
			final boolean moveBcToFront = prioritizeBc && bcProvider != null && originalBcPosition != null && originalBcPosition > 1;

			if (moveBcToFront)
			{
				Security.removeProvider(BC_PROVIDER);
				Security.insertProviderAt(bcProvider, 1);
			}
			try (ByteArrayInputStream stream = new ByteArrayInputStream(bytes))
			{
				final KeyStore keyStore = prioritizeBc && bcProvider != null ?
					KeyStore.getInstance(KEYSTORE_INSTANCE, bcProvider) :
					KeyStore.getInstance(KEYSTORE_INSTANCE);
				keyStore.load(stream, password);
				return keyStore;
			}
			finally
			{
				if (moveBcToFront)
				{
					Security.removeProvider(BC_PROVIDER);
					Security.insertProviderAt(bcProvider, originalBcPosition);
				}
			}
		}
	}

	private static final class Attempt
	{
		private final String label;
		private final char[] password;
		private final boolean prioritizeBc;

		private Attempt(@NonNull final String label, @NonNull final char[] password, final boolean prioritizeBc)
		{
			this.label = label;
			this.password = password.clone();
			this.prioritizeBc = prioritizeBc;
		}

		@NonNull
		private KeyStore load(@NonNull final byte[] bytes) throws Exception
		{
			return loadKeyStore(bytes, password, prioritizeBc);
		}

		@NonNull
		private String describe(@NonNull final String providerName)
		{
			return label + " password=" + (password.length == 0 ? "empty" : "provided") + " provider=" + providerName;
		}

		@NonNull
		private String describeFailure(@NonNull final Exception exception)
		{
			return "PKCS#12 load failed using " + describe(prioritizeBc ? BC_PROVIDER : "default") +
				": " + exception.getClass().getSimpleName() + ": " + exception.getMessage();
		}
	}

	private Pkcs12KeyStoreLoader() {}
}


