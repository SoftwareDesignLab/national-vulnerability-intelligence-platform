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
package edu.rit.se.nvip.cvesource;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.crawler.CveCrawlController;
import edu.rit.se.nvip.crawler.urlcrawler.UrlCrawlController;
import edu.rit.se.nvip.cveprocess.CveLogDiff;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.NvipSource;
import edu.rit.se.nvip.model.UrlCrawlerData;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * Refresh the source URL list csv file at output/nvip_url_sources.csv
 * 
 * @author axoeec
 *
 */
public class UpdateNvipSourceUrlList {
	private static Logger logger = LogManager.getLogger(UpdateNvipSourceUrlList.class);

	/**
	 * Tune this depth to look for more URLs in a given seed URL. It is
	 * zero-indexed. 1 means second level of the search tree!
	 */
	private static final int SEARCH_DEPTH = 1;
//	private static final String seedFile = "nvip-seeds-test.txt";
	private static final String seedFile = "nvip-seeds.txt";
	private static boolean flushExistingUrls = true;

	public static void main(String[] args) {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		// use the seeds here to look for more source urls
		char separator = File.separatorChar;
		ClassLoader classLoader = UpdateNvipSourceUrlList.class.getClassLoader();
		InputStream inputStream = classLoader.getResourceAsStream(seedFile);
		if (inputStream == null) {
			logger.error("Could not read seed URLs from resources, exiting!");
			System.exit(1);
		}

		// String sourceUrlPath = "src/test/resources/cve-source-multiple-bugzilla.txt";
		String outputPath = propertiesNvip.getDataDir() + "/" + propertiesNvip.getNvipUrlSources(); // crawled url sources stored here

		// load URLs
		List<String> urls = null;
		try {
			urls = IOUtils.readLines(inputStream, "UTF-8");
			if (urls.isEmpty()) {
				logger.info("No seed URLs are provided, exiting!");
				System.exit(1);
			}
		} catch (IOException e) {
			logger.error("Please enter a correct input .txt file for seed URLs!");
			System.exit(1);
		}

		/**
		 * crawl
		 */
		UrlCrawlController crawlerController = new UrlCrawlController(propertiesNvip, SEARCH_DEPTH);
		UrlCrawlerData crawlerData = crawlerController.crawl(urls);
		List<String> crawledURLs = new ArrayList<String>(crawlerData.getHashMapLegitimateSourceURLs().keySet());

		/**
		 * log to file
		 */
		CveLogDiff cveLogger = new CveLogDiff(propertiesNvip);
		cveLogger.logCrawledURLs(crawledURLs, outputPath);

		/**
		 * store into database
		 */
		List<NvipSource> nvipSourceList = new ArrayList<NvipSource>();
		for (String sUrl : crawledURLs) {
			nvipSourceList.add(new NvipSource(sUrl, "", HttpStatus.SC_OK));
		}

		// sources not Ok?
		HashMap<String, Integer> notOkUrls = crawlerData.getHashMapSourceURLsNotOk();

		DatabaseHelper db = DatabaseHelper.getInstance();
		if (flushExistingUrls) {
			int count = db.flushNvipSourceUrl();
			logger.info("Removed existing {} source urls in db", count);
		}
		boolean done = db.insertNvipSource(nvipSourceList, notOkUrls);
		if (done)
			logger.info("NVIP source crawl URL process is DONE!");

	}

}
