package org.strongswan.android.logic;

import org.junit.Before;
import org.junit.Test;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.*;

public class SchedulerQueueTest
{
    private FakeAlarms alarms;
    private SchedulerQueue queue;
    private long now;
    private List<String> executed;
    private List<Boolean> modes;
    private List<String> failures;

    @Before
    public void setUp()
    {
        now = 1000;
        alarms = new FakeAlarms();
        executed = new ArrayList<>();
        modes = new ArrayList<>();
        failures = new ArrayList<>();
        queue = new SchedulerQueue(alarms, () -> now, executed::add, new SchedulerQueue.Diagnostics()
        {
            public void modeChanged(boolean exact) { modes.add(exact); }
            public void schedulingFailed(String operation, RuntimeException exception) { failures.add(operation); }
        });
    }

    @Test
    public void grantedAccessUsesExactDeadlineAndLogsModeOnlyOnce()
    {
        queue.scheduleJob("later", 200);
        queue.scheduleJob("earlier", 100);
        assertEquals(Arrays.asList(1200L, 1100L), alarms.exact);
        assertTrue(alarms.inexact.isEmpty());
        assertEquals(Arrays.asList(true), modes);
    }

    @Test
    public void deniedAccessUsesInexactOnInitialScheduleAndRearm()
    {
        alarms.allowed = false;
        queue.scheduleJob("first", 100);
        queue.scheduleJob("second", 200);
        now = 1100;
        queue.onAlarm();
        assertEquals(Arrays.asList(1100L, 1200L), alarms.inexact);
        assertEquals(Arrays.asList("first"), executed);
        assertTrue(alarms.exact.isEmpty());
    }

    @Test
    public void exactPermissionRaceFallsBackWithoutLosingTheJob()
    {
        alarms.rejectExact = true;
        queue.scheduleJob("job", 100);
        assertEquals(Arrays.asList(1100L), alarms.inexact);
        assertEquals(Arrays.asList(false), modes);
        now = 1100;
        queue.onAlarm();
        assertEquals(Arrays.asList("job"), executed);
    }

    @Test
    public void permissionCheckSecurityExceptionAlsoFallsBack()
    {
        alarms.rejectCheck = true;
        queue.scheduleJob("job", 100);
        assertEquals(Arrays.asList(1100L), alarms.inexact);
    }

    @Test
    public void accessIsRecheckedOnReceive()
    {
        queue.scheduleJob("first", 100);
        queue.scheduleJob("second", 200);
        alarms.allowed = false;
        now = 1100;
        queue.onAlarm();
        assertEquals(Arrays.asList(1200L), alarms.inexact);
        assertEquals(Arrays.asList(true, false), modes);
    }

    @Test
    public void grantRearmsTheEarliestPendingDeadlineWithoutExecutingJobs()
    {
        alarms.allowed = false;
        queue.scheduleJob("later", 300);
        queue.scheduleJob("earlier", 100);
        alarms.allowed = true;
        queue.onExactAlarmAccessChanged();
        assertEquals(Arrays.asList(1100L), alarms.exact);
        assertTrue(executed.isEmpty());
        assertEquals(Arrays.asList(false, true), modes);
    }

    @Test
    public void jobsRunOnceInDeadlineOrderEvenWhenAlarmArrivesLate()
    {
        queue.scheduleJob("third", 300);
        queue.scheduleJob("first", 100);
        queue.scheduleJob("second", 200);
        now = 1400;
        queue.onAlarm();
        queue.onAlarm();
        assertEquals(Arrays.asList("first", "second", "third"), executed);
    }

    @Test
    public void earlyAlarmPreservesJobsAndRearmsTheirOriginalDeadline()
    {
        queue.scheduleJob("first", 100);
        now = 1050;
        queue.onAlarm();
        assertTrue(executed.isEmpty());
        assertEquals(Arrays.asList(1100L, 1100L), alarms.exact);
    }

    @Test
    public void dueJobRunsDespiteCompleteRearmFailureAndLaterScheduleRetries()
    {
        queue.scheduleJob("due", 100);
        queue.scheduleJob("pending", 200);
        alarms.rejectExact = true;
        alarms.rejectInexact = true;
        now = 1100;
        queue.onAlarm();
        assertEquals(Arrays.asList("due"), executed);
        alarms.rejectExact = false;
        alarms.rejectInexact = false;
        // New job is later than the pending job; an unarmed queue still needs a retry.
        queue.scheduleJob("later", 500);
        assertEquals(Long.valueOf(1200), alarms.exact.get(alarms.exact.size() - 1));
        now = 1600;
        queue.onAlarm();
        assertEquals(Arrays.asList("due", "pending", "later"), executed);
    }

    @Test
    public void completeInitialFailureRollsBackTheJavaJobBeforeThrowing()
    {
        alarms.rejectExact = true;
        alarms.rejectInexact = true;
        assertThrows(IllegalStateException.class, () -> queue.scheduleJob("failed", 100));
        alarms.rejectExact = false;
        alarms.rejectInexact = false;
        queue.scheduleJob("valid", 200);
        assertEquals(Long.valueOf(1200), alarms.exact.get(alarms.exact.size() - 1));
        now = 1500;
        queue.onAlarm();
        assertEquals(Arrays.asList("valid"), executed);
    }

    @Test
    public void failedEarlierInsertionDoesNotRemoveExistingNativeJobs()
    {
        queue.scheduleJob("existing", 200);
        alarms.rejectExact = true;
        alarms.rejectInexact = true;
        assertThrows(IllegalStateException.class, () -> queue.scheduleJob("failed", 100));
        alarms.rejectExact = false;
        alarms.rejectInexact = false;
        queue.onExactAlarmAccessChanged();
        now = 1400;
        queue.onAlarm();
        assertEquals(Arrays.asList("existing"), executed);
    }

    @Test
    public void failedGrantRearmDoesNotEscapeTheBroadcast()
    {
        alarms.allowed = false;
        queue.scheduleJob("job", 100);
        alarms.rejectInexact = true;
        queue.onExactAlarmAccessChanged();
        assertFalse(failures.isEmpty());
        alarms.rejectInexact = false;
        now = 1100;
        queue.onAlarm();
        assertEquals(Arrays.asList("job"), executed);
    }

    @Test
    public void terminationCancelsOnceClearsJobsAndIgnoresLateBroadcasts()
    {
        queue.scheduleJob("job", 100);
        queue.terminate();
        queue.terminate();
        now = 2000;
        queue.onAlarm();
        queue.onExactAlarmAccessChanged();
        assertEquals(1, alarms.cancellations);
        assertTrue(executed.isEmpty());
        assertThrows(IllegalStateException.class, () -> queue.scheduleJob("late", 100));
    }

    private static class FakeAlarms implements SchedulerQueue.Alarms
    {
        boolean allowed = true, rejectCheck, rejectExact, rejectInexact;
        int cancellations;
        List<Long> exact = new ArrayList<>(), inexact = new ArrayList<>();
        public boolean canScheduleExactAlarms()
        {
            if (rejectCheck) throw new SecurityException();
            return allowed;
        }
        public void setExact(long deadline)
        {
            if (rejectExact) throw new SecurityException();
            exact.add(deadline);
        }
        public void setInexact(long deadline)
        {
            if (rejectInexact) throw new IllegalStateException("Alarm service unavailable");
            inexact.add(deadline);
        }
        public void cancel() { cancellations++; }
    }
}
