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
package edu.rit.se.nvip.cvereconcile;

import java.util.Calendar;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;

/**
 * Cve reconciliation and validation
 * 
 * @author Ahmet Okutan
 *
 */
public class CveReconciler {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public boolean isCveIdCorrect(String cveId) {
		// CVE-XXXX-YYYY
		String[] arr = cveId.split("-");
		boolean lengthOk = arr[1].length() >= 4 && arr[2].length() >= 4;
		boolean rangeOk = false;
		try {
			int year = Integer.parseInt(arr[1]);
			int currentYear = Calendar.getInstance().get(Calendar.YEAR);
			if (year >= 1999 && year <= (currentYear + 1))
				rangeOk = true;
		} catch (NumberFormatException e) {
			logger.error("Error!" + e.toString());
		}

		return lengthOk && rangeOk;
	}

	/**
	 * Add <newVuln> to <existingCveMap> if it does not already exist. If it exists
	 * already, update its fields based on the reconciliation heuristic.
	 * 
	 * @param existingCveMap
	 * @param newVuln
	 * @param bLogInfo
	 * @return
	 */
	public HashMap<String, CompositeVulnerability> addCrawledCveToExistingCveHashMap(HashMap<String, CompositeVulnerability> existingCveMap, CompositeVulnerability newVuln, boolean bLogInfo) {
		if (existingCveMap.containsKey(newVuln.getCveId())) {
			if (bLogInfo)
				logger.info("*** Existing CVE-ID: " + newVuln.getCveId() + "\tCVE:URL: " + newVuln.getSourceURL().get(0) + "\tPlatform: " + newVuln.getPlatform() + "\tDescription: "
						+ newVuln.getDescription());
			CompositeVulnerability existingVuln = existingCveMap.get(newVuln.getCveId());

			// reconcile, check if we have better attribute values and update?
			boolean reconciled = reconcileVulnerabilities(existingVuln, newVuln);
			if (reconciled)
				existingCveMap.put(existingVuln.getCveId(), existingVuln); // update hash map

		} else {
			existingCveMap.put(newVuln.getCveId(), newVuln);
			if (bLogInfo)
				logger.info(
						"***  New  ** CVE-ID: " + newVuln.getCveId() + "\tCVE:URL: " + newVuln.getSourceURL() + "\tPlatform: " + newVuln.getPlatform() + "\tDescription: " + newVuln.getDescription());
		}

		return existingCveMap;
	}

	/**
	 * Reconcile (Primitive approach for now). If <existingVuln> is updated, returns
	 * true. In any case it is safe to assume that <existingVuln> stores the
	 * reconciled attributes.
	 * 
	 * @param existingVuln
	 * @param newVuln
	 * @return
	 */
	public boolean reconcileVulnerabilities(CompositeVulnerability existingVuln, CompositeVulnerability newVuln) {
		boolean reconciled = false;
		if (existingVuln.getPlatform() == null && newVuln.getPlatform() != null) {
			existingVuln.setPlatform(newVuln.getPlatform());
			reconciled = true;
		}

		if (existingVuln.getPublishDate() == null && newVuln.getPublishDate() != null) {
			existingVuln.setPublishDate(newVuln.getPublishDate());
			reconciled = true;
		}

		if (existingVuln.getDescription() == null || existingVuln.getDescription().length() < newVuln.getDescription().length()) {
			existingVuln.setDescription(newVuln.getDescription());
			reconciled = true;
		}
		if (reconciled) {
			String newURL = newVuln.getSourceURL().get(0); // new vuln can have only one source url
			existingVuln.addSourceURL(newURL);
		}
		return reconciled;
	}
}
