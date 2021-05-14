/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.cnnvd;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.cloud.translate.Translate;
import com.google.cloud.translate.TranslateOptions;
import com.google.cloud.translate.Translation;
import com.opencsv.CSVWriter;

import edu.rit.se.nvip.model.CnnvdVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.UrlUtils;

/**
 * 
 * 
 * Cnnvd controller
 * 
 * @author axoeec
 *
 */
public class CnnvdCveController {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String sUrlForNumberOfPages = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag";
	String sUrlForCveListPage = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=$pageno$&repairLd=";
	String outputPath = null;
	String localPath = null;
	int numberOfThreads;

	List<CnnvdVulnerability> vulnerabilities = new ArrayList<CnnvdVulnerability>();

	public CnnvdCveController(String localPath, String outputPath, int numberOfThreads) {
		super();
		this.localPath = localPath;
		this.outputPath = outputPath;
		this.numberOfThreads = numberOfThreads;

	}

	public static void main(String[] args) {
		UrlUtils urlUtils = new UrlUtils();
		String str = "https://android.googlesource.com/platform/frameworks/av/+/7a3246b870ddd11861eda2ab458b11d723c7f62c";
		String bUrl = urlUtils.getBaseUrl(str);

	}

	/**
	 * get page from url
	 * 
	 * @param url
	 * @return
	 * @throws Exception
	 */
	private String getPageAsString(URL url) throws Exception {
		return IOUtils.toString(url);
	}

	/**
	 * get # of pages in CNNVD
	 * 
	 * @return
	 */
	public int getNumberOfPages() {
		int count = 0;
		try {
			String html = getPageAsString(new URL(sUrlForNumberOfPages));
			Document document = Jsoup.parse(html);
			Elements inputs = document.select("input[name=pagecount]");
			String str = inputs.get(0).attr("value");
			count = Integer.parseInt(str);
		} catch (Exception e) {
			logger.error("Error while getting # of pages from CNNVD: " + e.toString());
		}
		return count;
	}

	private String getCnnvdPageFileName(int pageNo) {
		return localPath + "cnnvd-page-" + pageNo + ".html";
	}

	private String getCnnvdCveDetailPageName(String cnnvdCveId) {
		return localPath + cnnvdCveId + ".html";
	}

	public int pullCnnvdCVEs(int startPageNumber, int pageCount) {
		// reset file
		List<String[]> header = new ArrayList<String[]>();
		header.add(new String[] { "CVE-ID", "CNNVD-ID", "Level", "Vuln Source", "Publish Date", "Update Date", "Page URL" });
		CsvUtils csvLogger = new CsvUtils();
		csvLogger.writeListToCSV(header, outputPath, false);

		// start a task for each page
		int pageIndex = startPageNumber;
		ExecutorService pool = Executors.newFixedThreadPool(numberOfThreads);
		while (pageIndex <= pageCount) {
			Runnable runnable = new CnnvdPageProcessor(pageIndex, pageCount);
			pool.execute(runnable);
			pageIndex++;
			try {
				TimeUnit.MILLISECONDS.sleep(50);
			} catch (InterruptedException ignore) {

			}
		}

		// shut down
		try {
			pool.shutdown();
			boolean done = pool.awaitTermination(600, TimeUnit.MINUTES);
			if (done)
				logger.info("Done! Scraped " + vulnerabilities.size() + " vulnerabilities from CNNVD!");
			else
				logger.error("Error! Scraped " + vulnerabilities.size() + " of " + (pageCount * 10) + " vulnerabilities from CNNVD!");
		} catch (InterruptedException e2) {
			logger.error("Error while awaiting task completion!" + e2.toString());

		}

		processAndLogCNNVDReferenceURLs(); // cnnvd ref URLs
		return vulnerabilities.size();
	}

	/**
	 * pull Cnnvd CVEs
	 * 
	 * @return
	 */
	public int pullCnnvdCVEs(int startPageNumber) {

		// get page count
		int pageCount = getNumberOfPages();
		logger.info("Starting to scrape " + pageCount + " CNNVD pages, starting at page " + startPageNumber);

		if (startPageNumber > pageCount) {
			logger.error("No such page at cnnvd.org!");
			return 0;
		}

		pullCnnvdCVEs(startPageNumber, pageCount);

		return vulnerabilities.size();
	}

	/**
	 *
	 * Get CNNVD reference URLS,
	 * 
	 * A URL my exist in the references of multiple CVEs, check uniqueness with a
	 * hash map! Also check if the URL is still reachable!
	 * 
	 */
	private void processAndLogCNNVDReferenceURLs() {
		UrlUtils urlUtils = new UrlUtils();
		try {
			CnnvdCveParser chinaCveParser = new CnnvdCveParser();
			logger.info("Collecting reference URLs from the scraped CNNVD CVEs...");

			int totScraped = 0;
			HashMap<String, Integer> fullRefUrlHash = new HashMap<String, Integer>();
			for (CnnvdVulnerability vuln : vulnerabilities) {
				List<String> urls = vuln.getVulnerabilitySource();
				for (String refUrl : urls) {
					if (StringUtils.countMatches(refUrl, "http") > 1) {
						List<String> subURLs = chinaCveParser.matchURLsFromText(refUrl);
						for (String subRefUrl : subURLs) {
							fullRefUrlHash.put(subRefUrl, 0);
							totScraped++;
						}
					} else {
						fullRefUrlHash.put(refUrl, 0);
						totScraped++;
					}
				}
			}

			// check if reachable?
			logger.info("Processing if " + fullRefUrlHash.keySet().size() + " URLs are valid...");
			List<String> listFullRefUrls = new ArrayList<String>();
			HashMap<String, Integer> baseRefUrlHash = new HashMap<String, Integer>();
			int count = 0;
			for (String sUrl : fullRefUrlHash.keySet()) {
				String sBaseUrl = urlUtils.getBaseUrl(sUrl);
				if (sBaseUrl != null) {
					listFullRefUrls.add(sUrl);
					baseRefUrlHash.put(sBaseUrl, 0);
				}

				count++;
				if (count % 10000 == 0)
					logger.info("Processed " + count + " URLs...");

			}

			List<String> listBaseRefUrls = new ArrayList<String>();

			for (String sUrl : baseRefUrlHash.keySet())
				listBaseRefUrls.add(sUrl);

			outputPath = outputPath.replace(".csv", "");
			outputPath = outputPath.substring(0, outputPath.lastIndexOf("/")) + "/url-sources/";
			FileUtils.writeLines(new File(outputPath + "cnnvd-cve-full-references.csv"), listFullRefUrls, false);
			FileUtils.writeLines(new File(outputPath + "cnnvd-cve-base-references.csv"), listBaseRefUrls, false);

			int totInvalid = fullRefUrlHash.keySet().size() - listFullRefUrls.size();
			logger.info("\nScraped " + totScraped + " total CNNVD full-reference URLs.\nThe # of unique full references: " + fullRefUrlHash.keySet().size() + "\nThe # of invalid full-references: " + totInvalid
					+ "\nThe # of recorded full-references " + listFullRefUrls.size() + "\nTotal # of unique base URLs: " + baseRefUrlHash.keySet().size());
		} catch (IOException e) {
			logger.error("Error while logging reference URLS: " + e.toString());
		}
	}

	/**
	 * convert list<ChinaVulnerability> to List<String[]>
	 * 
	 * @param pageVulnerabilities
	 * @param pageURL
	 * @return
	 */
	private List<String[]> getStringArrList(List<CnnvdVulnerability> pageVulnerabilities, String pageURL) {
		List<String[]> arr = new ArrayList<String[]>();

		for (CnnvdVulnerability vuln : pageVulnerabilities)
			arr.add(new String[] { vuln.getCveId(), vuln.getChinaCveId(), vuln.getHazardLevel(), Arrays.deepToString(vuln.getVulnerabilitySource().toArray()), vuln.getPublishDate(), vuln.getUpdateDate(), pageURL });

		return arr;

	}

	private String translate(String str) {
		Translate translate = TranslateOptions.getDefaultInstance().getService();

		Translation translation = translate.translate(str);
		return translation.getTranslatedText();
	}

	/**
	 * Process a Cnnvd page
	 * 
	 * @author 15854
	 *
	 */
	public class CnnvdPageProcessor implements Runnable {
		private int pageIndex;
		private int pageCount;

		public CnnvdPageProcessor(int pageIndex, int pageCount) {
			this.pageIndex = pageIndex;
			this.pageCount = pageCount;
		}

		// run process
		public void run() {
			getCnnvdPage();
		}

		private boolean getCnnvdPage() {
			String pageLink = null;
			List<CnnvdVulnerability> pageVulnerabilities = new ArrayList<CnnvdVulnerability>();
			CnnvdCveParser chinaCveParser = new CnnvdCveParser();

			try {
				String pageStr;
				File fileCnnvdPage = new File(getCnnvdPageFileName(pageIndex));
				if (fileCnnvdPage.exists()) {
					pageStr = FileUtils.readFileToString(fileCnnvdPage, "utf-8");

				} else {
					pageLink = sUrlForCveListPage.replace("$pageno$", pageIndex + "");
					URL pageURL = new URL(pageLink);
					pageStr = getPageAsString(pageURL);

					// log this page file for future reference and analysis
					FileUtils.writeStringToFile(fileCnnvdPage, pageStr, "utf-8");
				}

				List<String> cveURLsInPage = chinaCveParser.getCveUrlListFromPage(pageStr);
				/**
				 * get CVES on this page
				 */
				pageVulnerabilities.clear();
				URL cveDetailURL = null;

				int index = 0;
				while (index < cveURLsInPage.size()) {
					try {
						String cveURLItem = cveURLsInPage.get(index);
						String[] cveUrlParts = cveURLItem.split("=");
						String cnnvdCveId = cveUrlParts[1];

						String cveDetailHtml = null;
						File fileCveDetail = new File(getCnnvdCveDetailPageName(cnnvdCveId));
						if (fileCveDetail.exists()) {
							cveDetailHtml = FileUtils.readFileToString(fileCveDetail, "utf-8");

						} else {
							cveDetailURL = new URL(cveURLItem);
							cveDetailHtml = getPageAsString(cveDetailURL);
						}

						// get CVE details
						CnnvdVulnerability vuln = chinaCveParser.getCveDetailsFromPage(cveDetailHtml);

						// get ref urls
						List<String> refURLs = chinaCveParser.getCveReferencesFromPage(cveDetailHtml);
						for (String refUrl : refURLs)
							vuln.addVulnerabilitySource(refUrl);

						// add vuln
						pageVulnerabilities.add(vuln);

						// log this file for future reference and analysis
						if (!fileCveDetail.exists())
							FileUtils.writeStringToFile(new File(getCnnvdCveDetailPageName(vuln.getChinaCveId())), cveDetailHtml, "utf-8");

						index++;
					} catch (Exception e) {
						logger.error("Error while getting CVE details from " + cveDetailURL + ": " + e.toString());
						continue;
					}
				}

				logger.info("Scraped CNNVD page " + pageIndex + "/" + pageCount + ", pulled " + pageVulnerabilities.size() + " vulnerabilities...");
				vulnerabilities.addAll(pageVulnerabilities);
				writeToFile(pageVulnerabilities, pageLink);
				return true;

			} catch (Exception e) {
				logger.error("Error while getting page " + pageLink + ": " + e.toString());
				try {
					Thread.sleep(60000); // wait 1 minute before trying again
				} catch (InterruptedException e1) {
					logger.error("InterruptedException during Thread.sleep: " + e1.toString());
				}
				return getCnnvdPage();
			}

		}
	}

	private synchronized void writeToFile(List<CnnvdVulnerability> pageVulnerabilities, String pageLink) {
		/**
		 * Add pageVulnerabilities to csv file
		 */
		CsvUtils csvLogger = new CsvUtils();
		csvLogger.writeListToCSV(getStringArrList(pageVulnerabilities, pageLink), outputPath, true);
	}

}
