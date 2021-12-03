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
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.DailyRun;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * Find out the differences between the CVEs crawled during the last NVIP run
 * and CVEs from NVD, MITRE, and previous NVIP run
 * 
 * @author axoeec
 *
 */
public class CveLogDiff {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	MyProperties propertiesNvip = null;

	public CveLogDiff(MyProperties propertiesNvip) {
		this.propertiesNvip = propertiesNvip;
	}

	/**
	 * log crawled vulnerabilities:
	 * 
	 * (1)All crawled vulnerabilities as of today, (2) Crawled vulnerabilities that
	 * are not in NVD, (3) Crawled vulnerabilities that are not in MITRE, (4)
	 * Crawled vulnerabilities that are not in NVD and MITRE, (5) Based on the items
	 * in (4) vulnerabilities that are new today (compared to the previous run), (6)
	 * Based on the items in (4) vulnerabilities that disappeared today (compared to
	 * the previous run)
	 * 
	 * @param crawlStartTime
	 * @param crawlEndTime
	 * @param newCVEListMap
	 * @return
	 */
	public HashMap<String, List<Object>> logAndDiffCVEs(long crawlStartTime, long crawlEndTime, HashMap<String, List<Object>> newCVEListMap, DatabaseHelper databaseHelper, int runId) {

		try {
			
			Calendar cal = Calendar.getInstance();
			String subDirName = UtilHelper.getPastDayAsShortDate(cal, 0);

			File file = new File(propertiesNvip.getOutputDir() + "/" + subDirName);
			if (!file.exists())
				file.mkdir();

			CsvUtils csvLogger = new CsvUtils();

			String filepath;
			int totCount = 0;
			try {
				filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_all.csv";
				String[] header = new String[] { "CVE-ID", "Version", "Description", "SourceURL" };
				csvLogger.writeHeaderToCSV(filepath, header, false);

				List<Object> allCrawledCveData = newCVEListMap.get("all");
				totCount = csvLogger.writeObjectListToCSV(allCrawledCveData, filepath, true);
				if (totCount > 0)
					logger.info("\tWrote " + totCount + " CVEs to CSV: " + filepath);
			} catch (Exception e) {
				logger.error("Error while logging all CVEs to CSV!" + e.toString());
			}

			// CVEs not in NVD
			try {
				int count = 0;

				filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_not_in_nvd.csv";
				count = csvLogger.writeObjectListToCSV(newCVEListMap.get("nvd"), filepath, false);
				if (count > 0) {
					logger.info("\tWrote " + count + " New CVEs *** Not exist in NVD *** to CSV: " + filepath);
				}

				// CVEs not in MITRE
				filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_not_in_mitre.csv";
				count = csvLogger.writeObjectListToCSV(newCVEListMap.get("mitre"), filepath, false);
				if (count > 0) {
					logger.info("\tWrote " + count + " New CVEs *** Not exist in MITRE ***  to CSV: " + filepath);
				}

				// CVEs not in NVD & MITRE
				filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_not_in_nvd_and_mitre.csv";
				count = csvLogger.writeObjectListToCSV(newCVEListMap.get("nvd-mitre"), filepath, false);
				if (count > 0) {
					logger.info("\tWrote " + count + " New CVEs *** Not exist in NVD && MITRE ***  to CSV: " + filepath);
				}
			} catch (Exception e) {
				logger.error("Error while logging CVE differences from NVD/MITRE to CSV!" + e.toString());
			}

			/**
			 * log summary
			 */
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			String sSummary = "*** NVIP Run ***" + "\nDate: " + dateFormat.format(date) + "\nTotal crawl time (s): " + (crawlEndTime - crawlStartTime) / 1000 + "\nTotal time for analysis & database update (s): "
					+ (System.currentTimeMillis() - crawlEndTime) / 1000 + "\nTotal # of CVEs: " + totCount + "\nTotal # of CVEs (Not In NVD): " + newCVEListMap.get("nvd").size() + "\nTotal # of CVEs (Not In MITRE): "
					+ newCVEListMap.get("mitre").size() + "\nTotal # of CVEs (Not In Both): " + newCVEListMap.get("nvd-mitre").size();

			// log time gaps for NVD/MITRE if any?
			int countNvd = 0, countMitre = 0;

			try {
				File fileNvd = new File(propertiesNvip.getOutputDir() + "/" + subDirName + "/" + "TimeGap-NVD.txt");
				File fileMitre = new File(propertiesNvip.getOutputDir() + "/" + subDirName + "/" + "TimeGap-MITRE.txt");
				StringBuffer sbNvd = new StringBuffer("TimeGap\tCVE-ID\tLastModifiedTime\tSourceUrl\n");
				StringBuffer sbMitre = new StringBuffer("TimeGap\tCVE-ID\tLastModifiedTime\tSourceUrl\n");
				String line = null;
				for (Object obj : newCVEListMap.get("all")) {
					if (obj instanceof CompositeVulnerability) {
						CompositeVulnerability vuln = (CompositeVulnerability) obj;
						if (vuln.getTimeGapNvd() > 0) {
							line = vuln.getTimeGapNvd() + "\t" + vuln.getCveId() + "\t" + vuln.getLastModifiedDate() + "\t" + Arrays.deepToString(vuln.getSourceURL().toArray()) + "\n";
							sbNvd.append(line);
							countNvd++;
						}

						if (vuln.getTimeGapMitre() > 0) {
							line = vuln.getTimeGapMitre() + "\t" + vuln.getCveId() + "\t" + vuln.getLastModifiedDate() + "\t" + Arrays.deepToString(vuln.getSourceURL().toArray()) + "\n";
							sbMitre.append(line);
							countMitre++;
						}

					}
				}

				// log to files
				if (countNvd > 0)
					FileUtils.writeStringToFile(fileNvd, sbNvd.toString(), true);

				if (countMitre > 0)
					FileUtils.writeStringToFile(fileMitre, sbMitre.toString(), true);
			} catch (Exception e) {
				logger.error("Error while logging time gap details! " + e.toString());
			}

			// CVEs New Today & CVEs disappeared: In the not in [NVD & MITRE] list
			sSummary += logCveDifferencesComparedToPrevRun(newCVEListMap.get("nvd-mitre"), csvLogger, subDirName, databaseHelper, runId);
			sSummary += "\nToday " + countNvd + " and " + countMitre + " CVE entries appeared at NVD and MITRE feeds, respectively!";

			// write summary info to file
			filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/" + "Readme.txt";
			FileUtils.writeStringToFile(new File(filepath), sSummary);
			logger.info(sSummary);

		} catch (Exception e) {
			logger.error("Error in logAndDiffCVEs(): " + e.toString());
		}

		return newCVEListMap;
	}

	/**
	 * Compare todays Not in [NVD and Mitre] list against yesterdays Not in [NVD and
	 * Mitre] list and log the CVEs that (1) Appeared (2) Disappeared today!
	 * 
	 * @param newCVENotExistAnyWhereToday
	 * @param csvLogger
	 * @param subDirName
	 * @param dailyRunStats               TODO
	 */
	private String logCveDifferencesComparedToPrevRun(List<Object> newCVENotExistAnyWhereToday, CsvUtils csvLogger, String subDirName, DatabaseHelper databaseHelper, int runId) {
		StringBuffer sBuffer = new StringBuffer();
		try {
			Calendar cal = Calendar.getInstance();
			int days = 1;
			int dayLimit = 30;

			// locate previous output if any
			File pathPreviousNvipResults = null;
			while (days < dayLimit) {
				String sDate = UtilHelper.getPastDayAsShortDate(cal, days);
				pathPreviousNvipResults = new File(propertiesNvip.getOutputDir() + "/" + sDate + "/cve_not_in_nvd_and_mitre.csv");
				if (pathPreviousNvipResults.exists())
					break;

				days++;
			}
			if (!pathPreviousNvipResults.exists()) {
				sBuffer.append("\nThere is no output for yesteday to compare against!");
				logger.info(sBuffer.toString());
				return sBuffer.toString();
			}

			List<String> arrPrevNvipResults = FileUtils.readLines(pathPreviousNvipResults);

			HashSet<String> setCveIdPrevious = new HashSet<String>();
			HashSet<String> setCveIdToday = new HashSet<String>();

			for (String cve : arrPrevNvipResults) {
				String id = cve.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				setCveIdPrevious.add(id);
			}

			for (Object item : newCVENotExistAnyWhereToday) {
				String id = ((Vulnerability) item).getCveId(); // get the the CVE ID
				setCveIdToday.add(id);
			}

			setCveIdToday.removeAll(setCveIdPrevious); // setCveIdToday now contains only the lines which are not in
														// setCveIdPrevious

			// filter the ones from yesterdays list that are new!
			List<Object> cveNewToday = new ArrayList<Object>();
			for (int index = 0; index < newCVENotExistAnyWhereToday.size(); index++) {

				String cveId = ((Vulnerability) newCVENotExistAnyWhereToday.get(index)).getCveId();
				if (setCveIdToday.contains(cveId))
					cveNewToday.add(newCVENotExistAnyWhereToday.get(index));
			}

			// log the new ones
			String filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_new_today.csv";
			int count = csvLogger.writeObjectListToCSV(cveNewToday, filepath, false);
			String str = "";
			if (count > 0) {
				str = "\n" + count + " CVEs appeared in (not in[nvd and mitre]) list today.";

			} else
				str = "\nNo new CVEs (not in[nvd and mitre]) today *** !";
			

			sBuffer.append(str);
			logger.info(str);

			// now log the ones that were there before but not now
			for (Object item : newCVENotExistAnyWhereToday) {
				String id = ((Vulnerability) item).getCveId(); // get the first item, i.e. the CVE ID
				setCveIdToday.add(id);
			}
			setCveIdPrevious.removeAll(setCveIdToday); // setCveIdPrevious now contains only the lines which are not in
														// setCveIdToday
			// filter CVEs from yesterday that disappeared today!
			List<String> arrPrev = FileUtils.readLines(pathPreviousNvipResults);
			List<String> cveDisappearedToday = new ArrayList<String>();
			for (int index = 0; index < arrPrev.size(); index++) {
				String row = arrPrev.get(index);
				String cveId = row.split(csvLogger.getSeparatorCharAsRegex())[0]; // get the first item, i.e. the CVE ID
				if (setCveIdPrevious.contains(cveId))
					cveDisappearedToday.add(row);
			}

			// Now arrPrev gives CVEs that disappeared today
			filepath = propertiesNvip.getOutputDir() + "/" + subDirName + "/cve_disappeared_today.csv";
			// new File(filepath).createNewFile();
			FileUtils.writeLines(new File(filepath), cveDisappearedToday, false);
			if (cveDisappearedToday.size() > 0)
				str = "\n" + cveDisappearedToday.size() + " CVEs disappeared from the (not in[nvd and mitre]) list today.";
			else
				str = "\nNo CVEs disappeared from the (not in[nvd and mitre]) list today *** !";
			sBuffer.append(str);
			logger.info(str);
		} catch (Exception e) {
			logger.error("Error in logCveDifferencesComparedToPrevRun(): " + e.toString());
			return (e.toString());
		}

		return sBuffer.toString();

	}

	/**
	 * Update the list of crawled URLs so far!
	 * 
	 * @param newList
	 * @param crawlUrlSourcesPath
	 */
	public void logCrawledURLs(List<String> newList, String crawlUrlSourcesPath) {

		HashMap<String, Integer> hashMapAllURLs = new HashMap<String, Integer>();
		int countPrev = 0, countNew = newList.size(), countCombined = 0;

		try {

			File file = new File(crawlUrlSourcesPath);
			if (!file.exists())
				file.createNewFile();

			// load old list
			List<String> prevList = FileUtils.readLines(new File(crawlUrlSourcesPath));
			for (String url : prevList)
				hashMapAllURLs.put(url, 0);
			countPrev = prevList.size();

			// append new ones
			for (Object url : newList)
				hashMapAllURLs.put((String) url, 0);

			// get combined list from hash map
			List<String> combinedList = new ArrayList<String>();
			for (String key : hashMapAllURLs.keySet())
				combinedList.add(key);

			FileUtils.writeLines(file, combinedList, false);
			countCombined = combinedList.size();

			logger.info("Refreshed crawl URL list at: " + crawlUrlSourcesPath + ", # of URLS: Existing: " + countPrev + ", Current: " + countNew + ", Combined: " + countCombined);

			String sourceUrlPathNvipResources = "src/main/resources/cvesources/nvip-url-sources.csv";
			FileUtils.writeLines(new File(sourceUrlPathNvipResources), combinedList, false);
			logger.info("Logged " + countCombined + " source URLs to " + sourceUrlPathNvipResources);

		} catch (IOException e) {
			logger.error("Error while refreshing crawled URLs: " + e.toString());
		}
	}

}
