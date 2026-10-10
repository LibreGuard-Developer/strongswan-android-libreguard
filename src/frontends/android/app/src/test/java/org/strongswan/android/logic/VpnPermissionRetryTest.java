package org.strongswan.android.logic;

import org.junit.Test;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import static org.junit.Assert.*;

public class VpnPermissionRetryTest {
    @Test public void permissionLossNeverSchedulesAnAutomaticRetry() throws Exception {
        Class<?> provider = Class.forName("org.strongswan.android.logic.VpnStateService$RetryTimeoutProvider");
        Constructor<?> constructor = provider.getDeclaredConstructor();
        constructor.setAccessible(true);
        Object instance = constructor.newInstance();
        Method timeout = provider.getDeclaredMethod("getTimeout", VpnStateService.ErrorState.class);
        timeout.setAccessible(true);
        assertTrue((long)timeout.invoke(instance, VpnStateService.ErrorState.UNREACHABLE) > 0);
        assertEquals(0L, (long)timeout.invoke(instance, VpnStateService.ErrorState.VPN_PERMISSION_REQUIRED));
        assertEquals(0L, (long)timeout.invoke(instance, VpnStateService.ErrorState.VPN_PERMISSION_REVOKED));
    }
}
