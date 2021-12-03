package edu.rit.se.nvip.utils;

import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.opencsv.CSVReader;

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
	private Logger logger = LogManager.getLogger(VendorAssessment.class);

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		VendorAssessment vendorAnalyzer = new VendorAssessment();
		String cvePath = vendorAnalyzer.initCvePath();
		vendorAnalyzer.refreshAdvisoriesAndPatches(cvePath);

		// "Quectel";// "SimCom";//"Espressif";//NXP, TI, Microchip
		//String[] vendors = new String[] { "Espressif", "NXP", "Microchip" };
		String[] vendors = new String[] {"STMicroelectronics"};
		if (args.length > 0)
			vendors = args[0].split(",");

		List<String[]> additionalCvesForVendors = new ArrayList<>();
//		String[] espressifCVEs = new String[] { "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26146", "CVE-2020-26147", "CVE-2020-24586", "CVE-2021-27926", "CVE-2020-15048", "CVE-2020-13629",
//				"CVE-2021-31571", "CVE-2020-26555", "CVE-2020-26558", "CVE-2020-26556", "CVE-2020-26560", "CVE-2020-26559", "CVE-2020-26557", "CVE-2021-27926", "CVE-2021-34173" };
//		additionalCvesForVendors.add(espressifCVEs);
//		additionalCvesForVendors.add(new String[] {});
		additionalCvesForVendors.add(new String[] {});

		vendorAnalyzer.filterCVEs(vendors, cvePath, additionalCvesForVendors);
		vendorAnalyzer.calcVendorMetrics(vendors);

	}

	private String initCvePath() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		// refresh CVEs from NVD (including patches/advisories)
		return propertiesNvip.getDataDir()+ "/nvd-cve.csv";
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

			logger.info("Adding CVEs for {} to {}", vendor, outputDataPath);

			logger.info("Initializing exploit scraper...");
			ExploitScraper exploitScraper = ExploitScraper.getInstance();
			logger.info("Done!");

			logger.info("Filtering CVEs...");
			List<String[]> cveData = csvUtils.getDataFromCsv(fileCve);
			int count = 0;
			try {
				// truncate file
				Files.writeString(Paths.get(outputDataPath), "", Charset.forName("ISO-8859-1"));

				// add header
				String header = "CveId,cvss,description,advisory,patch,exploit\n";
				Files.writeString(Paths.get(outputDataPath), header, Charset.forName("ISO-8859-1"), StandardOpenOption.APPEND);

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
						String exploitUrl = tokens[9];

						List<Exploit> exploitList = exploitScraper.getExploits(cveId);
						if (exploitList.size() > 0)
							for (Exploit exploit : exploitList)
								exploitUrl = exploitUrl + exploit.getPublisherUrl() + ";";

						String line = cveId + "," + cvss + "," + description + "," + advisories + "," + patches + "," + exploitUrl + "\n";
//					line = line.replace(";", ",");
						Files.writeString(Paths.get(outputDataPath), line, Charset.forName("ISO-8859-1"), StandardOpenOption.APPEND);
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

		public CveStatYear(int cveCount, int patchCount, int advisoryCount, int exploitCount) {
			super();
			this.cveCount = cveCount;
			this.patchCount = patchCount;
			this.advisoryCount = advisoryCount;
			this.exploitCount = exploitCount;
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
		for (String vendor : vendorList) {

			try {
				Map<String, CveStatYear> vendorMap = new HashMap<>();
				if (cveStatMap.containsKey(vendor))
					vendorMap = cveStatMap.get(vendor);

				// csv file for vendor
				String vendorData = getDataPath() + "/vendors/" + vendor + ".csv";

				List<String[]> cveData = csvUtils.getDataFromCsv(vendorData, ',');
				int count = 0;

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

		try {
			// truncate file
			Files.writeString(Paths.get(outputMetricsPath), "", Charset.forName("ISO-8859-1"));

			// add header
			String header = "vendor,year,cve count,advisory count,patch count,exploit count\n";
			Files.writeString(Paths.get(outputMetricsPath), header, Charset.forName("ISO-8859-1"), StandardOpenOption.APPEND);

			for (String vendor : cveStatMap.keySet()) {
				Map<String, CveStatYear> vendorData = cveStatMap.get(vendor);

				SortedSet<String> keySet = new TreeSet<>(vendorData.keySet());

				for (String year : keySet) {
					CveStatYear stat = vendorData.get(year);
					String line = vendor + "," + year + "," + stat.cveCount + "," + stat.advisoryCount + "," + stat.patchCount + "," + stat.exploitCount + "\n";
					Files.writeString(Paths.get(outputMetricsPath), line, Charset.forName("ISO-8859-1"), StandardOpenOption.APPEND);
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		logger.info("Created output for vendors {} at {}", Arrays.deepToString(vendorList), outputMetricsPath);

	}

}
