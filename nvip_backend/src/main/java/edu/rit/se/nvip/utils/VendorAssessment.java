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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import edu.rit.se.nvip.exploit.ExploitScraper;
import edu.rit.se.nvip.model.Exploit;
import edu.rit.se.nvip.nvd.NvdCveController;

/**
 * This program takes a vendor (company) or product name as input and searches
 * all related CVEs, exploits and patches
 * 
 * @author 15854
 *
 */
public class VendorAssessment {
	private final Logger logger = LogManager.getLogger(VendorAssessment.class);

	public static void main(String[] args) {

		VendorAssessment vendorAnalyzer = new VendorAssessment();
		String cvePath = vendorAnalyzer.initCvePath();
		vendorAnalyzer.refreshAdvisoriesAndPatches(cvePath);

		String[] vendors = new String[] { "NXP" };
		if (args.length > 0)
			vendors = args[0].split(",");

		List<String[]> additionalCvesForVendors = new ArrayList<>();
		additionalCvesForVendors.add(new String[] {});

		vendorAnalyzer.filterCVEs(vendors, cvePath, additionalCvesForVendors);
		vendorAnalyzer.calcVendorMetrics(vendors);

	}

	private String initCvePath() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		// refresh CVEs from NVD (including patches/advisories)
		return propertiesNvip.getDataDir() + "/nvd-cve.csv";
	}

	private String getDataPath() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		// refresh CVEs from NVD (including patches/advisories)
		return propertiesNvip.getDataDir();
	}

	/**
	 * refresh CVEs, Advisories, Patches etc
	 */
	private void refreshAdvisoriesAndPatches(String cvePath) {
		new NvdCveController().pullNvdCve(cvePath, false);
	}

	/**
	 * Filter CVEs for Vendor and write them to /vendors/<vendor>.csv. CSV file
	 * includes each CVE, its description, related advisories, patches and exploits
	 * 
	 * @param vendor
	 * @param fileCve
	 */
	private void filterCVEs(String[] vendorList, String fileCve, List<String[]> additionalCvesForVendors) {
		CsvUtils csvUtils = new CsvUtils();

		for (int i = 0; i < vendorList.length; i++) {
			String vendor = vendorList[i];
			String outputDataPath = getDataPath() + "/vendors/" + vendor + ".csv";

			if (!(new File(outputDataPath)).exists()) {
				logger.warn("No csv file found for vendor {}", vendor);
				continue;
			}

			logger.info("Adding CVEs for {} to {}", vendor, outputDataPath);

			logger.info("Initializing exploit scraper...");
			ExploitScraper exploitScraper = ExploitScraper.getInstance();
			logger.info("Done!");

			logger.info("Filtering CVEs...");
			List<String[]> cveData = csvUtils.getDataFromCsv(fileCve);
			int count = 0;
			try (FileWriter fw = new FileWriter(outputDataPath, true)) {
				// add header
				String header = "CveId,cvss,description,advisory,patch,exploit\n";
				fw.write(header);

				for (String[] tokens : cveData) {

					// CSV Columns:
					// "CVE-ID", "Description", "BaseScore", "BaseSeverity", "ImpactScore",
					// "ExploitabilityScore", "CWE", "Advisory", "Patch"

					String cveId = tokens[0];
					String description = tokens[1];
					String cvss = tokens[2];

					boolean includeCve = false;
					String[] vendorCVEs = additionalCvesForVendors.get(i);
					for (String cve : vendorCVEs)
						if (cve.trim().equalsIgnoreCase(cveId.trim()))
							includeCve = true;

					if (description.contains(vendor) || includeCve) {
						count++;
						String advisories = tokens[7];
						String patches = tokens[8];
						StringBuilder exploitUrl = new StringBuilder(tokens[9]);

						List<Exploit> exploitList = exploitScraper.getExploits(cveId);
						if (exploitList.size() > 0)
							for (Exploit exploit : exploitList)
								exploitUrl.append(exploit.getPublisherUrl()).append(";");

						String line = cveId + "," + cvss + "," + description + "," + advisories + "," + patches + "," + exploitUrl + "\n";
						fw.write(line);
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

			logger.info("{} CVEs recorded at {} for {}", count, outputDataPath, vendor);
		}

	}

	private class CveStatYear {
		int cveCount = 0;
		int patchCount = 0;
		int advisoryCount = 0;
		int exploitCount = 0;

		public CveStatYear() {

		}

		public void incCveCount(int cveCount) {
			this.cveCount += cveCount;
		}

		public void incPatchCount(int patchCount) {
			this.patchCount += patchCount;
		}

		public void incAdvisoryCount(int advisoryCount) {
			this.advisoryCount += advisoryCount;
		}

		public void incExploitCount(int exploitCount) {
			this.exploitCount += exploitCount;
		}

	}

	/**
	 * Output a CSV file that gives the yearly advisories, patches and exploits for
	 * each vendor.
	 * 
	 * @param vendorList
	 */
	public void calcVendorMetrics(String[] vendorList) {
		CsvUtils csvUtils = new CsvUtils();

		Map<String, Map<String, CveStatYear>> cveStatMap = new HashMap<>();

		String outputMetricsPath = getDataPath() + "/vendors/vendors.csv";
		if (!(new File(outputMetricsPath)).exists()) {
			logger.warn("No vendor data at {}", outputMetricsPath);
			return;
		}

		for (String vendor : vendorList) {

			try {
				Map<String, CveStatYear> vendorMap = new HashMap<>();
				if (cveStatMap.containsKey(vendor))
					vendorMap = cveStatMap.get(vendor);

				// csv file for vendor
				String vendorData = getDataPath() + "/vendors/" + vendor + ".csv";

				List<String[]> cveData = csvUtils.getDataFromCsv(vendorData, ',');
				if (cveData == null) {
					logger.warn("No data found for vendor {} at path {}", vendor, vendorData);
					continue;
				}

				// csv columns: CveId, cvss, description, advisory, patch, exploit
				for (int i = 1; i < cveData.size(); i++) { // skip header
					String[] tokens = cveData.get(i);

					String cveId = tokens[0];
					String advisories = tokens[3];
					String patches = tokens[4];
					String exploits = tokens[5];

					// calc metrics
					int nAdvisory = 0;
					if (advisories != null && advisories.length() > 0)
						nAdvisory = advisories.split(";").length;

					int nPatch = 0;
					if (patches != null && patches.length() > 0)
						nPatch = patches.split(";").length;

					int nExploit = 0;
					if (exploits != null && exploits.length() > 0)
						nExploit = exploits.split(";").length;

					String year = cveId.split("-")[1];

					CveStatYear cveStat = new CveStatYear();
					if (vendorMap.containsKey(year))
						cveStat = vendorMap.get(year);

					cveStat.incCveCount(1);
					cveStat.incPatchCount(nPatch);
					cveStat.incAdvisoryCount(nAdvisory);
					cveStat.incExploitCount(nExploit);

					vendorMap.put(year, cveStat); // update year data for vendor

				} // for each CVE

				cveStatMap.put(vendor, vendorMap); // update vendor map
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			logger.info("Calculated yearly stats for vendors {}", Arrays.deepToString(vendorList));
		}

		try (FileWriter fw = new FileWriter(outputMetricsPath, true)) {

			// add header
			String header = "vendor,year,cve count,advisory count,patch count,exploit count\n";
			fw.write(header);

			for (String vendor : cveStatMap.keySet()) {
				Map<String, CveStatYear> vendorData = cveStatMap.get(vendor);

				SortedSet<String> keySet = new TreeSet<>(vendorData.keySet());

				for (String year : keySet) {
					CveStatYear stat = vendorData.get(year);
					String line = vendor + "," + year + "," + stat.cveCount + "," + stat.advisoryCount + "," + stat.patchCount + "," + stat.exploitCount + "\n";
					fw.write(line);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		logger.info("Created output for vendors {} at {}", Arrays.deepToString(vendorList), outputMetricsPath);

	}

}
