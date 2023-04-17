/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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
import java.util.*;

import org.apache.commons.collections4.SetUtils;
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
	public static final String ALL_CVE_KEY = "all";
	public static final String NVD_CVE_KEY = "nvd";
	public static final String MITRE_CVE_KEY = "mitre";
	public static final String NVD_MITRE_CVE_KEY = "nvd-mitre";

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private Set<String> cvesInNvd = new HashSet<>();
	private Set<String> cvesInMitre = new HashSet<>();

	CveReconciler cveUtils = new CveReconciler();

	public CveProcessor(Set<String> nvdCves, Set<String> mitreCves){
		this.cvesInNvd = nvdCves;
		this.cvesInMitre = mitreCves;
	}

	public CveProcessor(String nvdCvePath, String mitreCvePath) {
		try {

			CsvUtils csvLogger = new CsvUtils();
			/**
			 * NVD
			 */
			List<String> arrNVD = FileUtils.readLines(new File(nvdCvePath));
			for (String cve : arrNVD) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				cvesInNvd.add(id);
			}

			/**
			 * MITRE
			 */
			arrNVD = FileUtils.readLines(new File(mitreCvePath));
			for (String cve : arrNVD) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				cvesInMitre.add(id);
			}

		} catch (IOException e) {
			logger.error("Error while loading NVD/MITRE CVEs!" + e);
			System.exit(1); // This is a serious error, exit!
		}
		logger.info("Loaded cve data for NVD(" + cvesInNvd.size() + ") and MITRE(" + cvesInNvd.size() + ")");
	}

	/**
	 * Process CVEs to identify the ones not in NVD and MITRE
	 *
	 * @param hashMapNvipCve
	 * @return
	 */
	public HashMap<String, List<Object>> checkAgainstNvdMitre(Map<String, CompositeVulnerability> hashMapNvipCve) {

		HashMap<String, List<Object>> newCVEMap = new HashMap<>();
		logger.info("Comparing with NVD and MITRE");
		// get list from hash map
		Set<Object> allCveData = new HashSet<>();
		Set<Object> newCVEDataNotInMitre = new HashSet<>();
		Set<Object> newCVEDataNotInNvd = new HashSet<>();

		for (CompositeVulnerability vuln : hashMapNvipCve.values()) {
			try {
				// If somehow a wrong CVE id is found, ignore it
				if (!cveUtils.isCveIdCorrect(vuln.getCveId())) {
					String note = "Wrong CVE ID! Check for typo? ";
					vuln.setNvipNote(note);
					logger.warn("WARNING: The CVE ID {} found at {} does not appear to be valid!", vuln.getCveId(), Arrays.deepToString(vuln.getSourceURL().toArray()));
					continue;
				}

				allCveData.add(vuln);

				if(vuln.isFoundNewDescriptionForReservedCve()) {
					logger.info("CVE: {} has new description for Reserved Cve", vuln.getCveId());
					vuln.setMitreStatus(1);
					vuln.setNvdStatus(1);
					newCVEDataNotInMitre.add(vuln);
					newCVEDataNotInNvd.add(vuln);
					continue;
				}

				if(cvesInNvd.contains(vuln.getCveId())){
					logger.info("CVE: {} is in NVD: Setting status to 1", vuln.getCveId());
					vuln.setNvdStatus(1);
				} else {
					logger.info("CVE: {}, is NOT in NVD", vuln.getCveId());
					vuln.setNvdSearchResult("NA");
					newCVEDataNotInNvd.add(vuln);
				}

				if(cvesInMitre.contains(vuln.getCveId())){
					logger.info("CVE: {} is in NVD: Setting status to 1", vuln.getCveId());
					vuln.setMitreStatus(1);
				} else {
					logger.info("CVE: {}, is NOT in NVD", vuln.getCveId());
					vuln.setNvdSearchResult("NA");
					newCVEDataNotInMitre.add(vuln);
				}

			} catch (Exception e) {
				logger.error("ERROR: Error while checking against NVD/MITRE, CVE: {}", vuln.getCveId());
			}
		}

		newCVEMap.put("all", Arrays.asList(allCveData.toArray())); // all CVEs
		newCVEMap.put("mitre", Arrays.asList(newCVEDataNotInMitre.toArray())); // CVEs not in Mitre
		newCVEMap.put("nvd", Arrays.asList(newCVEDataNotInNvd.toArray())); // CVEs not in Nvd
		newCVEMap.put("nvd-mitre", Arrays.asList(SetUtils.intersection(newCVEDataNotInMitre, newCVEDataNotInNvd).toArray())); // CVEs not in Nvd and Mitre

		logger.info("Out of {} total valid CVEs crawled: \n{} does not appear in NVD, \n{} does not appear in MITRE and \n{} are not in either!",
				newCVEMap.get(ALL_CVE_KEY).size(),
				newCVEMap.get(NVD_CVE_KEY).size(),
				newCVEMap.get(MITRE_CVE_KEY).size(),
				newCVEMap.get(NVD_MITRE_CVE_KEY).size());

		return newCVEMap;
	}

}
