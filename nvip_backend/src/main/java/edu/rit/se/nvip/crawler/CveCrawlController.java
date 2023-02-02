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
package edu.rit.se.nvip.crawler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.cvereconcile.AbstractCveReconciler;
import edu.rit.se.nvip.cvereconcile.CveReconcilerFactory;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.UtilHelper;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;

/**
 * Crawl controller implementation
 * 
 * @author axoeec
 *
 */
public class CveCrawlController {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	MyProperties propertiesNvip;
	public static final String DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0";

	AbstractCveReconciler cveUtils;
	CveReconcilerFactory reconcileFactory = new CveReconcilerFactory();

	public CveCrawlController(MyProperties propertiesNvip) {
		super();
		this.propertiesNvip = propertiesNvip;
		logger.info("Nvip is using CVE Reconciliation method: {} ", propertiesNvip.getCveReconciliationMethod());
		cveUtils = reconcileFactory.createReconciler(propertiesNvip.getCveReconciliationMethod());
	}

	/**
	 * Crawl provided <urls> and look for CVEs
	 * 
	 * @param urls
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public HashMap<String, CompositeVulnerability> crawl(List<String> urls) {
		HashMap<String, CompositeVulnerability> cveHashMapAll = new HashMap<>();
		String crawlStorageFolder = propertiesNvip.getOutputDir() + "/crawler1";
		String crawlStorageFolder2 = propertiesNvip.getOutputDir() + "/crawler2";
		int numberOfCrawlers = propertiesNvip.getNumberOfCrawlerThreads();

		try {
			// set crawl params
			logger.info("Initializing crawl controllers...");
			CrawlController controller = getCrawlController(crawlStorageFolder, propertiesNvip.getDefaultCrawlerPoliteness());
			CrawlController delayedController = getCrawlController(crawlStorageFolder2, propertiesNvip.getDelayedCrawlerPoliteness());

			logger.info("Controllers initialized. Adding {} seed urls to crawl controller...", urls.size());
			// add seed urls
			int count = 0, countDelayed = 0;
			for (String url : urls) {
				if (UtilHelper.isDelayedUrl(url)) {
					delayedController.addSeed(url);
					countDelayed++;
				} else {
					controller.addSeed(url);
					count++;
					// logger.info("Adding seed: " + url);
				}

				if ((count + countDelayed) % 500 == 0)
					logger.info("Added {} of {} seed URLs...", (count + countDelayed), urls.size());
			}
			logger.info("{} and {} seed URLs added to the 'Default' and 'Delayed' crawlers! Initializing crawler factories...", count, countDelayed);

			// Create crawler factories.
			CrawlController.WebCrawlerFactory<CveCrawler> factory = () -> new CveCrawler(propertiesNvip);
			CrawlController.WebCrawlerFactory<CveCrawler> factory2 = () -> new CveCrawler(propertiesNvip);

			logger.info("Starting NVIP CVE Crawler with {} seed URLs and {} threads!", urls.size(), numberOfCrawlers);

			// Start default crawler. It is blocking!
			controller.start(factory, numberOfCrawlers);
			logger.info("Fetching CVEs from regular crawler");
			cveHashMapAll = getVulnerabilitiesFromCrawlerThreads(controller, cveHashMapAll);

			// Start delayed crawler. It is blocking!
			delayedController.start(factory2, numberOfCrawlers);
			logger.info("Fetching CVEs from delayed crawler");
			cveHashMapAll = getVulnerabilitiesFromCrawlerThreads(delayedController, cveHashMapAll);

		} catch (Exception e) {
			logger.error("Error!" + e);
		}
		return cveHashMapAll;
	}

	/**
	 * Get CVEs from crawler controller and add them to cve map based on the
	 * reconciliation result
	 * 
	 * @param controller
	 * @param cveHashMapAll
	 * @return the updated map
	 */
	private synchronized HashMap<String, CompositeVulnerability> getVulnerabilitiesFromCrawlerThreads(CrawlController controller, HashMap<String, CompositeVulnerability> cveHashMapAll) {

		int cveCount = cveHashMapAll.size();
		List<Object> crawlersLocalData = controller.getCrawlersLocalData();
		logger.info("Adding CVEs from {} different crawlers to {} exiting CVEs", crawlersLocalData.size(), cveCount);

		HashMap<String, CompositeVulnerability> cveDataCrawler = null;
		int nCrawlerID = 1;
		int totCveCount = 0, crawlerCveCount = 0;

		for (Object crawlerData : crawlersLocalData) {
			try {
				cveDataCrawler = (HashMap<String, CompositeVulnerability>) crawlerData;

				crawlerCveCount = cveDataCrawler.values().size();
				logger.info("Crawler {} scraped {} CVEs.", nCrawlerID, crawlerCveCount);
				for (CompositeVulnerability newVuln : cveDataCrawler.values())
					cveHashMapAll = cveUtils.addCrawledCveToExistingCveHashMap(cveHashMapAll, newVuln, false);
			} catch (Exception e) {
				logger.error("Error while getting data from crawler {}\tcveDataCrawler: {}, Error: {} ", nCrawlerID, cveDataCrawler, e.toString());
			}
			nCrawlerID++;
			totCveCount += crawlerCveCount;
		}

		logger.info("Controller derived {} unique CVEs from {} crawlers and {} total CVEs. New CVE count: {}", (cveHashMapAll.size() - cveCount), crawlersLocalData.size(), totCveCount, cveHashMapAll.size());
		return cveHashMapAll;
	}

	/**
	 * Instantiate crawl controller
	 * 
	 * @param outputDirectory
	 * @param politeness
	 * @return
	 * @throws Exception
	 */
	private CrawlController getCrawlController(String outputDirectory, int politeness) throws Exception {
		CrawlConfig config = new CrawlConfig();
		config.setIncludeBinaryContentInCrawling(false);
		config.setMaxDepthOfCrawling(propertiesNvip.getCrawlSearchDepth());
		config.setUserAgentString(DEFAULT_USER_AGENT); // "Mozilla/5.0"
		config.setIncludeHttpsPages(true);
		config.setPolitenessDelay(politeness);
		config.setCrawlStorageFolder(outputDirectory);

		PageFetcher pageFetcher = new PageFetcher(config);
		RobotstxtConfig robotstxtConfig = new RobotstxtConfig();
		RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig, pageFetcher);
		return new CrawlController(config, pageFetcher, robotstxtServer);
	}

}