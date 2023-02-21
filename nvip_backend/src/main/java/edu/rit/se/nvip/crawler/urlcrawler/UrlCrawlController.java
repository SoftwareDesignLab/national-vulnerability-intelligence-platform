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
package edu.rit.se.nvip.crawler.urlcrawler;

import java.io.File;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.FileUtils;
import edu.rit.se.nvip.model.UrlCrawlerData;
import edu.rit.se.nvip.utils.MyProperties;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * Url crawl controller
 * 
 * @author axoeec
 *
 */
public class UrlCrawlController {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	MyProperties propertiesNvip;
	int searchDepth = 1;

	public UrlCrawlController(MyProperties propertiesNvip, int searchDepth) {
		super();
		this.propertiesNvip = propertiesNvip;
		this.searchDepth = searchDepth;
	}

	/**
	 * Crawl provided <urls> to look for new CVE sources only
	 * 
	 * @param urls
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public UrlCrawlerData crawl(List<String> urls) {

		HashMap<String, Integer> legitimateUrlsAll = new HashMap<>();
		HashMap<String, Integer> forbiddenUrlsAll = new HashMap<>();
		HashMap<String, Integer> notOkUrlsAll = new HashMap<>();

		String crawlStorageFolder = propertiesNvip.getOutputDir();
		int numberOfCrawlers = propertiesNvip.getNumberOfCrawlerThreads() * 2;

		try {
			// set crawl params
			CrawlConfig config = new CrawlConfig();
			config.setIncludeBinaryContentInCrawling(false);
			config.setMaxDepthOfCrawling(searchDepth);
			config.setIncludeHttpsPages(true);
			config.setPolitenessDelay(propertiesNvip.getDefaultCrawlerPoliteness());
			config.setCrawlStorageFolder(crawlStorageFolder);


			// Instantiate the controller for this crawl.
			PageFetcher pageFetcher = new PageFetcher(config);
			RobotstxtConfig robotstxtConfig = new RobotstxtConfig();

			robotstxtConfig.setEnabled(false); // added by AO to test

			RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig, pageFetcher);
			CrawlController controller = new CrawlController(config, pageFetcher, robotstxtServer);
			long start = System.currentTimeMillis();

			// add seed urls
			logger.info("Adding " + urls.size() + " seed URLs...");
			int addedSeeds = 0;
			for (String url : urls) {
				if (url.lastIndexOf("ftp://") >= 0) // ignore ftp seeds
					continue;
				controller.addSeed(url);
				addedSeeds++;

				if (addedSeeds % 50 == 0)
					logger.info("Added " + addedSeeds + " seed URLs so far!");
			}

			logger.info("Added " + addedSeeds + " of " + urls.size() + " total seed URLs! Ignored " + (urls.size() - addedSeeds) + " of them!");

			// Create instances of crawlers.
			CrawlController.WebCrawlerFactory<UrlCrawler> factory = UrlCrawler::new;

			// Start the crawl. This is a blocking operation
			logger.info("Starting NVIP URL Crawler with " + urls.size() + " seed URLs and " + numberOfCrawlers + " threads!");
			controller.start(factory, numberOfCrawlers);

			/**
			 * The blocking crawl operation ends here. Get results from crawler threads!
			 */
			List<Object> crawlersLocalData = controller.getCrawlersLocalData();
			logger.info("Merging URLs from " + crawlersLocalData.size() + " different crawlers!");

			HashMap<String, Integer> legitimateUrlsFromCrawler;
			HashMap<String, Integer> forbiddenUrlsFromCrawler;
			HashMap<String, Integer> notOkUrlsFromCrawler;

			int nCrawlerID = 1;
			int totUrlCount = 0, crawlerUrlCount;

			for (Object crawlerData : crawlersLocalData) {

				// get legitimate
				legitimateUrlsFromCrawler = ((UrlCrawlerData) crawlerData).getHashMapLegitimateSourceURLs();
				crawlerUrlCount = legitimateUrlsFromCrawler.keySet().size();
				totUrlCount += crawlerUrlCount;

				legitimateUrlsAll.putAll(legitimateUrlsFromCrawler);

				// get forbidden
				forbiddenUrlsFromCrawler = ((UrlCrawlerData) crawlerData).getHashMapForbiddenSourceURLs();
				forbiddenUrlsAll.putAll(forbiddenUrlsFromCrawler);

				// get source URLs Not OK
				notOkUrlsFromCrawler = ((UrlCrawlerData) crawlerData).getHashMapSourceURLsNotOk();
				notOkUrlsAll.putAll(notOkUrlsFromCrawler);

				logger.info("Crawler " + nCrawlerID + " has found " + crawlerUrlCount + " legitimate and " + forbiddenUrlsFromCrawler.size() + " forbidden URLs!");
				nCrawlerID++;
			}

			long totalTime = (System.currentTimeMillis() - start) / 60000;

			logger.info("NVIP derived " + legitimateUrlsAll.keySet().size() + " unique legitimate URLs from " + crawlersLocalData.size() + " crawlers. Total URL count: " + totUrlCount + ", Elapsed time (min): " + totalTime);

			/**
			 * log forbidden URLs, check them periodically, why getting 403?
			 */
			String forbiddenUrlFile = "logs/URLsNotCrawled-Forbidden-403.txt";
			logger.info(forbiddenUrlsAll.keySet().size() + " forbidden URLs (403) are logged to: " + forbiddenUrlFile);
			FileUtils.writeLines(new File(forbiddenUrlFile), forbiddenUrlsAll.keySet());

			/**
			 * log Not HTTP200 URLs, check them periodically, why getting <> HTTP_OK ?
			 */
			String notOkUrlFile = "logs/NVIPSources-NotHTTP200.txt";
			logger.info(notOkUrlsAll.keySet().size() + " URLs with Http Status <> 200 are logged to: " + notOkUrlFile);
			FileUtils.writeLines(new File(notOkUrlFile), notOkUrlsAll.keySet());

		} catch (Exception e) {
			logger.error("Errer!" + e);
		}

		return new UrlCrawlerData(legitimateUrlsAll, forbiddenUrlsAll, notOkUrlsAll);
	}

}