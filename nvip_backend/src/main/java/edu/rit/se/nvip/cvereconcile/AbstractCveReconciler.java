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
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;

/**
 * Abstract class for Cve reconciliation and validation
 * 
 * @author Igor Khokhlov
 *
 */
public abstract class AbstractCveReconciler {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	protected Map<String, Integer> knownCveSources = new HashMap<>();

	public boolean isCveIdCorrect(String cveId) {
		// CVE-XXXX-YYYY
		String[] arr = cveId.split("-");
		boolean lengthOk = arr[1].length() >= 4 && arr[2].length() >= 4;
		boolean rangeOk = false;
		try {
			int year = Integer.parseInt(arr[1]);
			int currentYear = Calendar.getInstance().get(Calendar.YEAR);
			if (year >= 1999 && year <= currentYear)
				rangeOk = true;
		} catch (NumberFormatException e) {
			logger.error("Error: {}", e.toString());
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
				logger.info("*** Existing CVE: {}\tCVE:URL: {}\tDescription: {}", newVuln.getCveId(), newVuln.getSourceURL().get(0), newVuln.getDescription());
			CompositeVulnerability existingVuln = existingCveMap.get(newVuln.getCveId());

			// reconcile, check if we have better attribute values and update?
			boolean reconciled = reconcileVulnerabilities(existingVuln, newVuln);
			if (reconciled)
				existingCveMap.put(existingVuln.getCveId(), existingVuln); // update hash map

		} else {
			existingCveMap.put(newVuln.getCveId(), newVuln);
			if (bLogInfo)
				logger.info("***  New  ** CVE-ID: " + newVuln.getCveId() + "\tCVE:URL: " + newVuln.getSourceURL() + "\tPlatform: " + newVuln.getPlatform() + "\tDescription: " + newVuln.getDescription());
		}

		return existingCveMap;
	}

	/**
	 * Reconcile. If <existingVuln> is updated, returns true. In any case it is safe
	 * to assume that <existingVuln> stores the reconciled attributes.
	 * 
	 * @param existingVuln
	 * @param newVuln
	 * @return
	 */
	public abstract boolean reconcileVulnerabilities(CompositeVulnerability existingVuln, CompositeVulnerability newVuln);

	/**
	 * Reconcile by description only. If <existingDescription> is updated, returns
	 * true.
	 * 
	 * @param existingDescription  description of existing CVE
	 * @param newDescription       description of new CVE
	 * @param existingSourceDomain source domain of existing CVE
	 * @param newSourceDomain      source domain of new CVE
	 * @param considerSources      consider sources during reconciliation
	 * @return
	 */
	public abstract boolean reconcileDescriptions(String existingDescription, String newDescription, String existingSourceDomain, String newSourceDomain, boolean considerSources);

}
