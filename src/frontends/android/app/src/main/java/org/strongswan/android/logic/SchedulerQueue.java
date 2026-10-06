/*
 * Copyright (C) 2020 Tobias Brunner
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.fsf.org/copyleft/gpl.txt>.
 */
package org.strongswan.android.logic;

import java.util.ArrayList;
import java.util.PriorityQueue;

/** Queue and alarm policy, independent of Android so failure paths can be tested. */
final class SchedulerQueue
{
    interface Alarms
    {
        boolean canScheduleExactAlarms();
        void setExact(long deadline);
        void setInexact(long deadline);
        void cancel();
    }

    interface Clock { long now(); }
    interface Executor { void execute(String id); }
    interface Diagnostics
    {
        void modeChanged(boolean exact);
        void schedulingFailed(String operation, RuntimeException exception);
    }

    private final Alarms mAlarms;
    private final Clock mClock;
    private final Executor mExecutor;
    private final Diagnostics mDiagnostics;
    private final PriorityQueue<ScheduledJob> mJobs = new PriorityQueue<>();
    private boolean mArmed;
    private boolean mTerminated;
    private Boolean mExactMode;

    SchedulerQueue(Alarms alarms, Clock clock, Executor executor, Diagnostics diagnostics)
    {
        mAlarms = alarms;
        mClock = clock;
        mExecutor = executor;
        mDiagnostics = diagnostics;
    }

    synchronized void scheduleJob(String id, long ms)
    {
        if (mTerminated)
        {
            throw new IllegalStateException("Scheduler is terminated");
        }
        ScheduledJob job = new ScheduledJob(id, mClock.now() + ms);
        mJobs.add(job);
        if (job == mJobs.peek() || !mArmed)
        {
            try
            {
                armNext();
            }
            catch (RuntimeException exception)
            {
                // JNI destroys the native job on failure; do not retain a ghost entry.
                mJobs.remove(job);
                // An earlier job may still need an alarm after this failed replacement.
                rearmSafely();
                throw exception;
            }
        }
    }

    synchronized void onAlarm()
    {
        if (mTerminated)
        {
            return;
        }
        mArmed = false;
        ArrayList<ScheduledJob> due = new ArrayList<>();
        long now = mClock.now();
        while (!mJobs.isEmpty() && mJobs.peek().time <= now)
        {
            due.add(mJobs.remove());
        }
        // Re-arming errors must not prevent due jobs from reaching the native processor.
        rearmSafely();
        for (ScheduledJob job : due)
        {
            mExecutor.execute(job.id);
        }
    }

    synchronized void onExactAlarmAccessChanged()
    {
        if (!mTerminated)
        {
            rearmSafely();
        }
    }

    synchronized void terminate()
    {
        if (mTerminated)
        {
            return;
        }
        mTerminated = true;
        mJobs.clear();
        mArmed = false;
        mAlarms.cancel();
    }

    private void rearmSafely()
    {
        try
        {
            armNext();
        }
        catch (RuntimeException exception)
        {
            // Retain future native jobs. A later schedule or grant broadcast retries them.
            mDiagnostics.schedulingFailed("rearm", exception);
        }
    }

    private void armNext()
    {
        ScheduledJob job = mJobs.peek();
        if (job == null)
        {
            return;
        }
        mArmed = false;
        try
        {
            boolean exact;
            try
            {
                exact = mAlarms.canScheduleExactAlarms();
            }
            catch (SecurityException exception)
            {
                mDiagnostics.schedulingFailed("check exact access", exception);
                exact = false;
            }
            if (exact)
            {
                try
                {
                    mAlarms.setExact(job.time);
                    recordMode(true);
                    mArmed = true;
                    return;
                }
                catch (SecurityException exception)
                {
                    // Access may have changed between checking and setting the alarm.
                    mDiagnostics.schedulingFailed("exact access changed; using inexact", exception);
                }
            }
            mAlarms.setInexact(job.time);
            recordMode(false);
            mArmed = true;
        }
        catch (RuntimeException exception)
        {
            mDiagnostics.schedulingFailed("schedule", exception);
            throw exception;
        }
    }

    private void recordMode(boolean exact)
    {
        if (mExactMode == null || mExactMode != exact)
        {
            mExactMode = exact;
            mDiagnostics.modeChanged(exact);
        }
    }

    private static final class ScheduledJob implements Comparable<ScheduledJob>
    {
        final String id;
        final long time;
        ScheduledJob(String id, long time) { this.id = id; this.time = time; }
        @Override
        public int compareTo(ScheduledJob other) { return Long.compare(time, other.time); }
    }
}
