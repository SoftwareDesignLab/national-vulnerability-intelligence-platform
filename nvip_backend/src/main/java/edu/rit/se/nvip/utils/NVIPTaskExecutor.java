/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.utils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.NVIPMain;

/**
 * 
 * This class can be used to run NVIP periodically, two times every day!
 * 
 * @author axoeec
 *
 */
public class NVIPTaskExecutor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
	NVIPMain myTask;
	volatile boolean isStopIssued;

	public NVIPTaskExecutor(NVIPMain nvip) {
		myTask = nvip;
	}

	/**
	 * start the task at hour:minute:second
	 * 
	 * @param hour
	 * @param minute
	 * @param second
	 */
	public void start() {
		Runnable taskWrapper = new Runnable() {

			@Override
			public void run() {
				logger.info("NVIPMain is running at: " + (new Date().toString()));
				myTask.startNvip();
				start();
			}

		};
		long seconds = secondsToTheNextRun();
		scheduledExecutorService.schedule(taskWrapper, seconds, TimeUnit.SECONDS);
	}

	/**
	 * delay to the next run (12 hours later!)
	 * 
	 * @param hour
	 * @param minute
	 * @param second
	 * @return
	 */
	private long secondsToTheNextRun() {
		LocalDateTime localNow = LocalDateTime.now();
		ZoneId currentZone = ZoneId.systemDefault();
		ZonedDateTime now = ZonedDateTime.of(localNow, currentZone);

		ZonedDateTime target1159 = now.withHour(11).withMinute(59).withSecond(0);
		ZonedDateTime target2359 = now.withHour(23).withMinute(59).withSecond(0);

		ZonedDateTime target = null;
		if (now.compareTo(target1159) > 0)
			target = target2359; // now is afternoon, run at mid night
		else
			target = target1159; // now is before noon, run at noon

		Duration duration = Duration.between(now, target).abs(); // absolute difference
		logger.info("NVIPMain is scheduled to run " + (duration.getSeconds() / 60) + " minutes later, at: " + target.getHour() + ":" + target.getMinute() + ":00");
		return duration.getSeconds();
	}

	/**
	 * stop the task
	 */
	public void stop() {
		scheduledExecutorService.shutdown();
		try {
			scheduledExecutorService.awaitTermination(1, TimeUnit.DAYS);
		} catch (InterruptedException ex) {
			logger.error("Error while stopping nvip!" + ex.toString());
		}
	}

}
