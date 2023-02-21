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
package edu.rit.se.nvip.cveprocess;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.cvereconcile.CveReconciler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;

/**
 * 
 * Process CVEs to identify the ones not in NVD and MITRE
 * 
 * @author axoeec
 *
 */
public class CveProcessor {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private final HashMap<String, Integer> hashMapNvdCve = new HashMap<>();
	private final HashMap<String, Integer> hashMapMitreCve = new HashMap<>();
	CveReconciler cveUtils = new CveReconciler();

	public CveProcessor(String nvdCvePath, String mitreCvePath) {
		try {

			CsvUtils csvLogger = new CsvUtils();
			/**
			 * NVD
			 */
			List<String> arrNVD = FileUtils.readLines(new File(nvdCvePath));
			for (String cve : arrNVD) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				hashMapNvdCve.put(id, 0);
			}

			/**
			 * MITRE
			 */
			arrNVD = FileUtils.readLines(new File(mitreCvePath));
			for (String cve : arrNVD) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				hashMapMitreCve.put(id, 0);
			}

		} catch (IOException e) {
			logger.error("Error while loading NVD/MITRE CVEs!" + e);
			System.exit(1); // This is a serious error, exit!
		}
		logger.info("Loaded cve data for NVD(" + hashMapNvdCve.size() + ") and MITRE(" + hashMapMitreCve.size() + ")");
	}

	/**
	 * Process CVEs to identify the ones not in NVD and MITRE
	 * 
	 * @param hashMapNvipCve
	 * @return
	 */
	public HashMap<String, List<Object>> checkAgainstNvdMitre(HashMap<String, CompositeVulnerability> hashMapNvipCve) {
		HashMap<String, List<Object>> newCVEMap = new HashMap<>();

		// get list from hash map
		List<Object> allCveData = new ArrayList<>();
		List<Object> newCVEDataNotInMitre = new ArrayList<>();
		List<Object> newCVEDataNotInNvd = new ArrayList<>();
		List<Object> newCVEDataNotInNvdAndMitre = new ArrayList<>();
		for (CompositeVulnerability vuln : hashMapNvipCve.values()) {

			try {
				// if somehow a wrong CVE id is found, ignore it
				if (!cveUtils.isCveIdCorrect(vuln.getCveId())) {
					String note = "Wrong CVE ID! Check for typo? ";
					vuln.setNvipNote(note);
					logger.warn("The CVE ID {} found at {} does not appear to be valid!", vuln.getCveId(), Arrays.deepToString(vuln.getSourceURL().toArray()));
					continue; // skip this CVE
				}

				/**
				 * [CVE does not exist in the NVD] OR [it is reserved etc. in NVD but NVIP found
				 * a description for it]
				 */
				if (!hashMapNvdCve.containsKey(vuln.getCveId()) || vuln.isFoundNewDescriptionForReservedCve()) {
					vuln.setNvdSearchResult("NA");

					int status = 0;
					if (vuln.isFoundNewDescriptionForReservedCve())
						status = -1;

					vuln.setNvdStatus(status);
					newCVEDataNotInNvd.add(vuln);
				}

				/**
				 * [CVE does not exist in the MITRE] OR [it is reserved etc. in MITRE but NVIP
				 * found a description for it]
				 */
				if (!hashMapMitreCve.containsKey(vuln.getCveId()) || vuln.isFoundNewDescriptionForReservedCve()) {
					vuln.setNvdSearchResult("NA");

					int status = 0;
					if (vuln.isFoundNewDescriptionForReservedCve())
						status = -1;

					vuln.setMitreStatus(status);
					newCVEDataNotInMitre.add(vuln);
				}

				// not in both?
				if (!vuln.doesExistInNvd() && !vuln.doesExistInMitre()) {
					newCVEDataNotInNvdAndMitre.add(vuln);
				}

				// add to all CVEs list
				allCveData.add(vuln);
			} catch (Exception e) {
				logger.error("Error while checking against NVD/MITRE, CVE: " + vuln.toString());
			}
		}

		newCVEMap.put("all", allCveData); // all CVEs
		newCVEMap.put("mitre", newCVEDataNotInMitre); // CVEs not in Mitre
		newCVEMap.put("nvd", newCVEDataNotInNvd); // CVEs not in Nvd
		newCVEMap.put("nvd-mitre", newCVEDataNotInNvdAndMitre); // CVEs not in Nvd and Mitre

		logger.info("Out of {} total valid CVEs crawled: {} do not appear in NVD, {} not in MITRE and {} not in Both!", allCveData.size(), newCVEDataNotInNvd.size(), newCVEDataNotInMitre.size(),
				newCVEDataNotInNvdAndMitre.size());

		return newCVEMap;
	}

}
