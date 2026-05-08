package org.strongswan.android.security;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
public class Pkcs12KeyStoreLoaderTest
{
@Test
public void testDetectProviderCompatibilityIssue()
{
final Throwable error = new IOException(
"error constructing MAC",
new InvalidKeyException("No installed provider supports this key: com.android.org.bouncycastle.jcajce.PKCS12Key")
);
assertTrue(Pkcs12KeyStoreLoader.looksLikeProviderCompatibilityIssue(error));
}
@Test
public void testIgnoreRegularWrongPasswordFailure()
{
final Throwable error = new IOException("keystore password was incorrect");
assertFalse(Pkcs12KeyStoreLoader.looksLikeProviderCompatibilityIssue(error));
}
@Test
public void testInvalidPkcs12BytesProduceFailureResult()
{
final Pkcs12KeyStoreLoader.LoadResult result = Pkcs12KeyStoreLoader.load(
"definitely-not-a-pkcs12".getBytes(StandardCharsets.UTF_8),
"secret".toCharArray()
);
assertFalse(result.isSuccess());
assertNotNull(result.getException());
}
}