/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Parse CVEs from anquanke.com
 * 
 * @author axoeec
 *
 */
public class AnquankeParser extends AbstractCveParser  {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Parse advisories listed to anquanke.com
	 * @param domainName - anquanke.com domain, like: https://www.anquanke.com/post/id/210200 for example
	 */
	public AnquankeParser(String domainName) {
		sourceDomainName = domainName;
	}

	/**
	 * Parse CVEs from anquanke.com
	 * @param sSourceURL - URL to parse
	 * @param sCVEContentHTML - HTML content to parse
	 * @return - List of CVEs
	 */
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();
		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			// get CVE from title h1 tag
			Element cveEl = document.select("h1:contains(CVE-)").first();
			if (cveEl == null) return vulnerabilities;
			// extract CVE from h1 tag using regex
			Pattern cvePattern = Pattern.compile(regexCVEID);
			Matcher cveMatcher = cvePattern.matcher(cveEl.text());
			String cve = "";
			if (cveMatcher.find())
				cve = cveMatcher.group();
			if (cve.isEmpty()) return vulnerabilities;

			// get date from publish p tag above
			String date = "";
			Element dateEl = document.select("p.publish").first();
			if (dateEl != null) {
				date = dateEl.text().split("发布时间 : ")[1];
			}

			// get description from a combination of title and blog post
			// at this point we already know the title is CVE-XXXX-XXXX : [Title details]
			StringBuilder description = new StringBuilder();
			description.append(cveEl.text().replace(cve, "").replace("：", "").trim());

			// for rest of desc. blog post varies either h2 comes first or there is text before it,
			// thus go until we see the second h2 tag under js-article div
			Element jsArticle = document.select("div#js-article").first();
			if (jsArticle != null) {
				int h2Count = 0;
				for (Element e : jsArticle.children()) {
					if (e.tagName().equals("h2")) {
						h2Count++;
						if (h2Count == 2) break;
					}
					if (h2Count == 1) {
						description.append(e.text());
					}
				}
			}

			vulnerabilities.add(new CompositeVulnerability(
					0, sSourceURL, cve, null, date, date, description.toString(), sourceDomainName
			));

		} catch (Exception e) {
			logger.error("An error occurred while parsing Anquanke URL: " + sSourceURL);
		}

		return vulnerabilities;
	}
}
