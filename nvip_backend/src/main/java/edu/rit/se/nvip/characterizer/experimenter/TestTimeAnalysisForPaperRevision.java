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
package edu.rit.se.nvip.characterizer.experimenter;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * This class was written to test how many CVEs used in timing analysis (for a
 * paper) exist in NVD.
 * 
 * And how many CVEs published in NVD (at 2020) exist in the NVIP platform.
 * 
 * @author axoeec
 *
 */
public class TestTimeAnalysisForPaperRevision {
	private static Logger logger = LogManager.getLogger(TestTimeAnalysisForPaperRevision.class);
	static int ID_CVES_AFTER = 24000;
	static int ID_CVES_BEFORE = 25000;

	/**
	 * Make sure these files are under the "paper-experiment-data" directory of the
	 * data path (nvip properties getDataDir())
	 */
	static String allNvdCveFile = "nvd-cve.csv";
	static String nvipCveListFile = "nvip_cve_list.csv";
	static String nvdTimeGapsFile = "nvd_time_gaps.csv";

	public static void main(String[] args) {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		UtilHelper.initLog4j(propertiesNvip);

		String nvdCvePath = propertiesNvip.getDataDir() + "/" + allNvdCveFile;

		CsvUtils csvLogger = new CsvUtils();
		// all NVD CVEs
		Map<String, Integer> hashMapNvdCve = new HashMap<String, Integer>();

		// CVEs published in NVID at 2020
		Map<String, Integer> hashMapNvdCve2020 = new HashMap<String, Integer>();

		/**
		 * load NVD CVEs
		 */
		try {
			List<String> arrNVD = FileUtils.readLines(new File(nvdCvePath));
			for (String cve : arrNVD) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				hashMapNvdCve.put(id, 0);

				if (id.contains("CVE-2020")) {
//					int num = Integer.parseInt(id.split("-")[2]);
//					if (num > ID_CVES_AFTER && num <= ID_CVES_BEFORE)
					hashMapNvdCve2020.put(id, 0);
				}

			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		/**
		 * load CVEs used in the time analysis (from paper)
		 */
		String timeAnalysisCVePath = propertiesNvip.getDataDir() + "/paper-experiment-data/" + nvdTimeGapsFile;

		Map<String, Integer> timeAnalysisMap = new HashMap<String, Integer>();
		try {
			List<String> list = FileUtils.readLines(new File(timeAnalysisCVePath));
			for (String cve : list) {
				String id = cve.split(",")[0]; // get the first item, i.e. the CVE ID
				timeAnalysisMap.put(id, 0);
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		int count = 0, totalCount = 0;
		for (String cve : timeAnalysisMap.keySet()) {
			if (hashMapNvdCve.get(cve) != null)
				count++;

			totalCount++;
		}

		logger.info("Out of " + totalCount + " CVEs used in timing analysis " + count + " of them exist in NVD. Percentage: " + (count * 1.0 / totalCount * 100));

		/**
		 * load all nvip CVEs (pulled from NVIP MySQL database)
		 */
		String nvipCVePath = propertiesNvip.getDataDir() + "/paper-experiment-data/" + nvipCveListFile;

		Map<String, Integer> nvipCveMap = new HashMap<String, Integer>();
		Map<String, Integer> nvipCveMap2020 = new HashMap<String, Integer>();
		try {
			List<String> list = FileUtils.readLines(new File(nvipCVePath));
			for (String cve : list) {
				String id = cve.split(",")[0]; // get the first item, i.e. the CVE ID
				nvipCveMap.put(id, 0);

				if (id.contains("CVE-2020")) {
//					int num = Integer.parseInt(id.split("-")[2]);
//					if (num > ID_CVES_AFTER && num <= ID_CVES_BEFORE)
					nvipCveMap2020.put(id, 0);
				}

			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		count = 0;
		totalCount = 0;
		for (String cve : hashMapNvdCve2020.keySet()) {
			if (nvipCveMap2020.get(cve.trim()) != null)
				count++;

			totalCount++;
		}

		logger.info("Out of " + totalCount + " 2020 CVEs in NVD " + count + " of them found in NVIP. Percentage: " + (count * 1.0 / totalCount * 100));

		count = 0;
		totalCount = 0;
		StringBuffer strCve = new StringBuffer();
		for (String cve : nvipCveMap2020.keySet()) {
			if (hashMapNvdCve2020.get(cve.trim()) != null)
				count++;
			else {
				strCve.append(cve + " \t");
			}

			totalCount++;
		}

		logger.info("Out of " + totalCount + " 2020 CVEs in NVIP " + count + " of them found in NVD. Percentage: " + (count * 1.0 / totalCount * 100));

		/**
		 * Some CVE Examples that NVIP found but do not exist at NVD (Reserved at
		 * Mitre):
		 * 
		 * CVE-2020-24490: https://access.redhat.com/security/cve/cve-2020-24490
		 * 
		 * CVE-2020-24455:
		 * https://www.whitesourcesoftware.com/vulnerability-database/CVE-2020-24455
		 * 
		 * CVE-2020-4440:
		 * https://www.ibm.com/blogs/psirt/security-bulletin-ibm-openpages-with-watson-has-addressed-a-reverse-tabnabbing-vulnerability-cve-2020-4440/
		 * 
		 * CVE-2020-27907: https://vuldb.com/?id.166291
		 * 
		 * CVE-2020-26063: https://vulmon.com/vulnerabilitydetails?qid=CVE-2020-26063
		 * 
		 * CVE-2020-24597: https://github.com/HoangKien1020/CVE-2020-24597
		 */
		logger.info("CVEs that do not appear at NVD: " + strCve.toString());
	}

}
