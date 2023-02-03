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

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.crawler.htmlparser.CveParserFactory;
import edu.rit.se.nvip.crawler.htmlparser.CveParserInterface;
import edu.rit.se.nvip.cvereconcile.AbstractCveReconciler;
import edu.rit.se.nvip.cvereconcile.CveReconcilerFactory;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.WebCrawler;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.WebURL;

/**
 * 
 * NVIP CVE Crawler
 * 
 * @author axoeec
 *
 */
public class CveCrawler extends WebCrawler {
	private final static Pattern FILTERS = Pattern.compile(".*(\\.(css|js|gif|jpg" + "|png|mp3|mp4|zip|gz))$");
	private HashMap<String, CompositeVulnerability> hashMapNvipCve = new HashMap<>();
	CveParserFactory parserFactory = new CveParserFactory();
	AbstractCveReconciler cveUtils;
	CveReconcilerFactory reconcileFactory = new CveReconcilerFactory();
	DatabaseHelper databaseHelper;
	NumberFormat formatter = new DecimalFormat("#0.000");
	private final Logger nvip_logger = LogManager.getLogger(getClass().getSimpleName());

	public CveCrawler(MyProperties propertiesNvip) {
		super();
		cveUtils = reconcileFactory.createReconciler(propertiesNvip.getCveReconciliationMethod());

		// initialize db
		databaseHelper = DatabaseHelper.getInstance();
	}

	/**
	 * This method receives two parameters. The first parameter is the page in which
	 * we have discovered this new url and the second parameter is the new url. You
	 * should implement this function to specify whether the given url should be
	 * crawled or not (based on your crawling logic).
	 */
	@Override
	public boolean shouldVisit(Page referringPage, WebURL url) {
		String href = url.getURL().toLowerCase();
		return !FILTERS.matcher(href).matches();
	}

	/**
	 * Page is ready to be processed.
	 */
	@Override
	public void visit(Page page) {
		String pageURL = page.getWebURL().getURL().trim();
		if (page.getParseData() instanceof HtmlParseData) {
			HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
			String html = htmlParseData.getHtml();

			synchronized (this) {
				// get vulnerabilities form page
				List<CompositeVulnerability> vulnerabilityList = parseWebPage(pageURL, html);

				if (vulnerabilityList.isEmpty()) {
					nvip_logger.warn("No CVEs found at {}! Removing it from DB...", pageURL);
					databaseHelper.deleteNvipSourceUrl(pageURL); // if we got no CVE from this URL, remove it from crawled URL list.
				} else
					for (CompositeVulnerability vulnerability : vulnerabilityList) // reconcile extracted CVEs
						hashMapNvipCve = cveUtils.addCrawledCveToExistingCveHashMap(hashMapNvipCve, vulnerability, false);

				long processedPageCount = getMyController().getFrontier().getNumberOfProcessedPages();
				if (processedPageCount > 0 && processedPageCount % 250 == 0) {
					long myQueueLength = getMyController().getFrontier().getNumberOfScheduledPages();
					String percent = formatter.format(processedPageCount / (myQueueLength * 1.0) * 100);
					nvip_logger.info("Crawler {} processed {} of total {} pages, %{} done!", getMyId(), processedPageCount, myQueueLength, percent);
				}

			}

		}

	}

	/**
	 * parse this page with an appropriate parser and return vulnerabilities found
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		// get parser and parse
		CveParserInterface parser = parserFactory.createParser(sSourceURL);
		return parser.parseWebPage(sSourceURL, sCVEContentHTML);
	}

	/**
	 * get Cve data from crawler thread
	 */
	@Override
	public Object getMyLocalData() {
		return hashMapNvipCve;
	}

}