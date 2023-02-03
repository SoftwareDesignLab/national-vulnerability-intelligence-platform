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

import java.time.Year;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.UrlCrawlerData;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.WebCrawler;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.WebURL;

/**
 * 
 * NVIP URL Crawler. Just look for URLs that contain a CVE-ID
 * 
 * @author axoeec
 *
 */
public class UrlCrawler extends WebCrawler {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private final static Pattern FILTERS = Pattern.compile(".*(\\.(css|js|gif|jpg" + "|png|mp3|mp4|zip|gz))$");

	/**
	 * Crawled URLs that include a CVEID (can be at depth>=0)
	 */
	private HashMap<String, Integer> hashMapSourceURLsFound = new HashMap<>();

	/**
	 * URLs that are forbidden (depth >=0). NVIP sources that have the same base URL
	 * with those should be marked, to have an adaptive crawler process
	 */
	private HashMap<String, Integer> hashMapForbiddenURLs = new HashMap<>();

	/**
	 * NVIP URLs (depth=0) with status code != HTTP_OK. Those URLs should be removed
	 * from the NVIP URL sources!
	 */
	private final HashMap<String, Integer> hashMapSourceURLsNotOk = new HashMap<>();
	Pattern pattern;
	static Map<String, Integer> ignoredDomains = null;

	public UrlCrawler() {
		super();
		String regexCVEID = "CVE-[0-9]+-[0-9]+";
		pattern = Pattern.compile(regexCVEID);

		synchronized (UrlCrawler.class) {
			if (ignoredDomains == null) {
				logger.info("Initializing ignored domains...");
				ignoredDomains = new HashMap<>();
				ignoredDomains.put("packetstorm", 1);
				ignoredDomains.put("tenable", 1);
				ignoredDomains.put("nvd.nist", 1);
				ignoredDomains.put("mitre", 1);
				ignoredDomains.put("seclists", 1);
				ignoredDomains.put("cnnvd.org", 1);
				ignoredDomains.put("cvedetails.com", 1);

			}
		}
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
		boolean crawl = !FILTERS.matcher(href).matches();

		// is the url from one of the ignored domains?
		boolean ignored = false;
		for (String domain : ignoredDomains.keySet()) {
			if (href.contains(domain)) {
				ignored = true;
				break;
			}
		}
		return crawl && !ignored;
	}

	/**
	 * This function is called when a page is fetched and ready to be processed.
	 */
	@Override
	public void visit(Page page) {
		String pageURL = page.getWebURL().getURL().trim();

		if (page.getParseData() instanceof HtmlParseData) {
			HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
			String text = htmlParseData.getText();
			boolean bHasCVE = pickURL(pageURL, text);

			// the lower the better
			byte priority = 127;
			if (bHasCVE)
				priority = 0;

			Set<WebURL> links = htmlParseData.getOutgoingUrls();

			for (WebURL wUrl : links) {
				wUrl.setPriority(priority);
			}
		}
	}

	/**
	 * pick page URL? It needs to have a CVE ID and be not picked before!
	 * 
	 * @param pageURL
	 * @param sContent
	 */
	private boolean pickURL(String pageURL, String sContent) {
		if (haveCveId(sContent, ignoredDomains)) {
			if (!hashMapSourceURLsFound.containsKey(pageURL)) {
				hashMapSourceURLsFound.put(pageURL, 0);
				if (hashMapSourceURLsFound.size() % 10 == 0)
					logger.info("This process has found " + hashMapSourceURLsFound.size() + " legitimate and " + hashMapForbiddenURLs.size() + " forbidden (403) URLs so far!");
			}
			return true;
		}
		return false;
	}

	@Override
	protected void handlePageStatusCode(WebURL webUrl, int statusCode, String statusDescription) {
		if (statusCode == HttpStatus.SC_FORBIDDEN) {
			logger.warn("***CRAWLER WARN! Could not get content from " + webUrl.getURL() + ", StatusCode: " + statusCode + ", StatusDescription:" + statusDescription);
			hashMapForbiddenURLs.put(webUrl.getURL(), 0);
		}

		// check base url status?
		if (webUrl.getDepth() == 0) {
			if (statusCode != HttpStatus.SC_OK) {
				hashMapSourceURLsNotOk.put(webUrl.getURL(), statusCode);
			}
		}
	}

	@Override
	public Object getMyLocalData() {
		return new UrlCrawlerData(hashMapSourceURLsFound, hashMapForbiddenURLs, hashMapSourceURLsNotOk);
	}

	/**
	 * Include the URL only if it is not among the ignored domains and has a recent
	 * CVE.
	 * 
	 * @param strContent
	 * @param ignoredDomains
	 * @return
	 */
	private boolean haveCveId(String strContent, Map<String, Integer> ignoredDomains) {
		// does the page include any recent CVEs
		Matcher cveMatcher = pattern.matcher(strContent);
		while (cveMatcher.find()) {
			String cveId = cveMatcher.group();
			String[] parts = cveId.split("-");
			int year = Integer.parseInt(parts[1]);
			if (Year.now().getValue() - year <= 1)
				return true;
		}

		return false;
	}

}