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
package edu.rit.se.nvip.crawler.htmlparser;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * Parse Bugzilla CVEs
 * 
 * @author axoeec
 *
 */
public class BugzillaParser extends AbstractCveParser implements CveParserInterface {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	
	public BugzillaParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<CompositeVulnerability>();

		if (sSourceURL.contains("www.bugzilla.org"))
			return vulnerabilities;

		/**
		 * page contains CVE?
		 */
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return vulnerabilities;

		vulnerabilities = parseVulnPage(uniqueCves, sSourceURL, sCVEContentHTML);

		return vulnerabilities;
	}

	/**
	 * Parse pages like: https://bugzilla.redhat.com/show_bug.cgi?id=968382
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<CompositeVulnerability> parseVulnPage(Set<String> uniqueCves, String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<CompositeVulnerability>();
		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description = "";
			String publishDate = null;
			String platform = "";
			String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

			Elements elements = document.select("title");
			description = elements.get(0).text() + "\n";

			elements = document.select("pre.bz_comment_text");

			for (Element element : elements) {
				// parse logic
				description += element.text() + "\n";
			}

			elements = document.select("th.field_label");

			for (Element element : elements) {
				// parse logic
				String str = element.text();
				if (str.contains("Modified:")) {
					try {
						Element e2 = element.nextElementSibling();
						publishDate = e2.text();
						publishDate = publishDate.split(" ")[0];

						publishDate = UtilHelper.longDateFormat.format(dateFormat_yyyy_MM_dd.parse(publishDate));
					} catch (Exception e) {
						logger.error("Error parsing date: " + publishDate + " at " + sSourceURL);
					}
				}
			}

			for (String cveId : uniqueCves)
				vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cveId, platform, publishDate, lastModifiedDate, description, sourceDomainName));
		} catch (Exception e) {
			logger.error("An error occurred while parsing Bugzilla URL: " + sSourceURL);
		}

		return vulnerabilities;
	}

}
