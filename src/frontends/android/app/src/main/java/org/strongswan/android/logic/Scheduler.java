/*
 * Copyright (C) 2020 Tobias Brunner
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

package org.strongswan.android.logic;

import android.annotation.SuppressLint;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.util.Log;

import java.util.UUID;

import androidx.annotation.RequiresApi;

public class Scheduler extends BroadcastReceiver
{
    private static final String EXECUTE_JOB = "org.strongswan.android.Scheduler.EXECUTE_JOB";
    private final Context mContext;
    private final AlarmManager mManager;
    private final SchedulerQueue mQueue;
    private boolean mRegistered;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    public Scheduler(Context context)
    {
        mContext = context;
        mManager = (AlarmManager)context.getSystemService(Context.ALARM_SERVICE);
        mQueue = new SchedulerQueue(new SchedulerQueue.Alarms()
        {
            @Override
            public boolean canScheduleExactAlarms()
            {
                return Build.VERSION.SDK_INT < Build.VERSION_CODES.S || mManager.canScheduleExactAlarms();
            }

            @Override
            @SuppressLint({"ScheduleExactAlarm", "MissingPermission"})
            public void setExact(long deadline)
            {
                // The host declares SCHEDULE_EXACT_ALARM; the queue checks access and catches revocation.
                mManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, deadline, createIntent());
            }

            @Override
            public void setInexact(long deadline)
            {
                mManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, deadline, createIntent());
            }

            @Override
            public void cancel()
            {
                mManager.cancel(createIntent());
            }
        }, System::currentTimeMillis, this::executeJob, new SchedulerQueue.Diagnostics()
        {
            @Override
            public void modeChanged(boolean exact)
            {
                Log.i("VpnScheduler", "Connection maintenance alarm mode: " + (exact ? "exact" : "inexact"));
            }

            @Override
            public void schedulingFailed(String operation, RuntimeException exception)
            {
                // No job IDs, deadlines, profile data or per-keepalive logging.
                Log.w("VpnScheduler", "Alarm " + operation + " failed: " + exception.getClass().getSimpleName());
            }
        });

        IntentFilter filter = new IntentFilter(EXECUTE_JOB);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            filter.addAction(AlarmManager.ACTION_SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        {
            mContext.registerReceiver(this, filter, Context.RECEIVER_NOT_EXPORTED);
        }
        else
        {
            mContext.registerReceiver(this, filter);
        }
        mRegistered = true;
    }

    /** Remove all pending jobs and unregister the receiver. Called via JNI. */
    public synchronized void Terminate()
    {
        try
        {
            mQueue.terminate();
        }
        finally
        {
            if (mRegistered)
            {
                mRegistered = false;
                mContext.unregisterReceiver(this);
            }
        }
    }

    /** Allocate a job ID. Called via JNI. */
    public String allocateId()
    {
        return UUID.randomUUID().toString();
    }

    private PendingIntent createIntent()
    {
        /* using component/class doesn't work with dynamic broadcast receivers */
        Intent intent = new Intent(EXECUTE_JOB);
        intent.setPackage(mContext.getPackageName());
        int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0;
        return PendingIntent.getBroadcast(mContext, 0, intent, flags);
    }

    /** Called via JNI from different threads. */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void scheduleJob(String id, long ms)
    {
        mQueue.scheduleJob(id, ms);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void onReceive(Context context, Intent intent)
    {
        if (EXECUTE_JOB.equals(intent.getAction()))
        {
            mQueue.onAlarm();
        }
        else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                 AlarmManager.ACTION_SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED.equals(intent.getAction()))
        {
            mQueue.onExactAlarmAccessChanged();
        }
    }

    /** Execute the job with the given ID. JNI signature must remain unchanged. */
    public native void executeJob(String id);
}
