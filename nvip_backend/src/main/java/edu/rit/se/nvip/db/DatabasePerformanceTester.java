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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.DbParallelProcessor;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * Test the performance of DB
 * 
 * @author axoeec
 *
 */
public class DatabasePerformanceTester {

	Logger logger = LogManager.getLogger(DatabasePerformanceTester.class);
	int NUMBER_OF_VULNS = 5000;

	public DatabasePerformanceTester() {
	}

	/**
	 * Test db performance with serial and parallel processing
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		DatabasePerformanceTester dbTestMain = new DatabasePerformanceTester();
		dbTestMain.testSerialProcessing();
		dbTestMain.tesParallelProcessing();

	}

	/**
	 * Test performance with one process
	 */
	void testSerialProcessing() {
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
		List<CompositeVulnerability> vulnList = getVulns();
		long start = System.currentTimeMillis();
		databaseHelper.recordVulnerabilityList(vulnList, 1);
		long end = System.currentTimeMillis();
		logger.info("DB insert time for " + vulnList.size() + " vulns: " + ((end - start)) + " mseconds!");

		start = System.currentTimeMillis();
		databaseHelper.recordVulnerabilityList(vulnList, 1);
		end = System.currentTimeMillis();
		logger.info("DB update time for " + vulnList.size() + " vulns: " + ((end - start)) + " mseconds!");

		// delete them
		for (CompositeVulnerability vuln : vulnList) {
			databaseHelper.deleteVulnSource(vuln.getCveId());
			databaseHelper.deleteVuln(vuln.getCveId());
		}

	}

	/**
	 * Generate test vulnerabilities
	 * 
	 * @return
	 */
	public List<CompositeVulnerability> getVulns() {
		List<CompositeVulnerability> vulnList = new ArrayList<CompositeVulnerability>();
		for (int i = 0; i < NUMBER_OF_VULNS; i++) {
			CompositeVulnerability vuln = new CompositeVulnerability(0, "url" + i, "CXX-XXXX-1" + i, "versio" + i, null, UtilHelper.longDateFormat.format(new Date()), "Content" + i, null);
			vulnList.add(vuln);
		}

		return vulnList;
	}

	/**
	 * Test performance with multiple processes
	 */
	void tesParallelProcessing() {
		/**
		 * test insert
		 */
		logger.info("\n\nTesting parallel execution!");
		List<CompositeVulnerability> vulnList = getVulns();

		new DbParallelProcessor().executeInParallel(vulnList, 1);
		new DbParallelProcessor().executeInParallel(vulnList, 1);

		// delete them all
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
		for (CompositeVulnerability vuln : vulnList) {
			databaseHelper.deleteVulnSource(vuln.getCveId());
			databaseHelper.deleteVuln(vuln.getCveId());
		}

	}

}
