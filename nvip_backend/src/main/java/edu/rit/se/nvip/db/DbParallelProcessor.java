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
package edu.rit.se.nvip.db;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.collections4.ListUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;

/**
 * 
 * 
 * Store CVEs with multi-threading
 * 
 * @author axoeec
 *
 */
public class DbParallelProcessor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public DbParallelProcessor() {

	}

	/**
	 * Generate a thread pool and run in parallel
	 * 
	 * @param vulnList
	 * @return
	 */
	public boolean executeInParallel(List<CompositeVulnerability> vulnList, int runId) {
		boolean done = false;
		long start = System.currentTimeMillis();

		int numOfRecordsPErThread = 25000;
		List<List<CompositeVulnerability>> vulnList2 = ListUtils.partition(vulnList, numOfRecordsPErThread);

		int numberOfThreads = vulnList.size() / numOfRecordsPErThread + 1;
		logger.info("Spawning {} threads to record {} CVEs", numOfRecordsPErThread, vulnList.size());
		ExecutorService pool = Executors.newFixedThreadPool(numberOfThreads);
		for (List<CompositeVulnerability> subList : vulnList2) {
			Runnable runnable = new VulnRecordThread(subList, runId);
			pool.execute(runnable);
		}

		// shut down pool
		try {
			pool.shutdown();
			done = pool.awaitTermination(180, TimeUnit.MINUTES);
			long end = System.currentTimeMillis();
			logger.info(getClass().getSimpleName() + " time for " + vulnList.size() + " items: " + ((end - start)) + " mseconds!");
			if (!done) {
				logger.error("A serious error has accurred! The parallel job was terminated due to timeout before DONE! Check log files!");
			}

			DatabaseHelper.clearExistingVulnMap(); // clear existing CVEs map!
		} catch (InterruptedException e2) {
			logger.error(
					"Error while awaiting task completion! # of threads: " + numberOfThreads + " # of lists in the partitioned large vuln list: " + vulnList2.size() + " Exception: " + e2.toString());
		}

		return done;
	}

	/**
	 * Store (insert or update) a set of CVEs.
	 * 
	 * @author Ahmet Okutan
	 *
	 */
	private class VulnRecordThread extends Thread implements Runnable {
		DatabaseHelper databaseHelper = null;
		private List<CompositeVulnerability> vulnList;
		private int runId = 0;

		public VulnRecordThread(List<CompositeVulnerability> vulnList, int runId) {
			this.vulnList = vulnList;
			this.runId = runId;
			databaseHelper = DatabaseHelper.getInstanceForMultiThreading();
		}

		// run process
		public void run() {
			logger.info("Active, Idle and Total connections BEFORE insert: " + databaseHelper.getConnectionStatus());
			databaseHelper.recordVulnerabilityList(vulnList, runId);
			logger.info("Active, Idle and Total connections AFTER insert (before shutdown): " + databaseHelper.getConnectionStatus());
			databaseHelper.shutdown();
		}
	}

}
