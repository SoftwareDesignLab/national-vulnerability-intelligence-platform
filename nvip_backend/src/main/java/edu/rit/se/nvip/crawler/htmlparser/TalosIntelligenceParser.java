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
 * Parse TalosIntelligence CVEs
 * 
 * @author Ahmet Okutan
 *
 */
public class TalosIntelligenceParser extends AbstractCveParser implements CveParserInterface {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	
	public TalosIntelligenceParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();

		if (sSourceURL.contains("blog.talosintelligence.com") || sSourceURL.contains("/newsletters/"))
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
	 * Parse pages like:
	 * https://talosintelligence.com/vulnerability_reports/TALOS-2020-1124
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<CompositeVulnerability> parseVulnPage(Set<String> uniqueCves, String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();
		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description = "";
			String publishDate = null;
			String platform = "";
			String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

			Elements allElements = document.select("h3");

			for (Element element : allElements) {
				String text = element.text();

				if (text.contains("Summary")) {
					String str = "";
					while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
						str += element.nextElementSibling().text();
						element = element.nextElementSibling();
					}
					description += str;
				}

				if (text.contains("Tested Versions")) {
					String str = "";
					if (element != null && element.nextElementSibling().tagName().equals("p")) {
						while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
							str += element.nextElementSibling().text();
							element = element.nextElementSibling();
						}
					} else {
						str = element.nextElementSibling().text();
					}
					platform += str;
				}

				if (text.contains("Details")) {
					String str = "";
					while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
						try {
							str += element.nextElementSibling().text();
							element = element.nextElementSibling();
						} catch (Exception e) {
						}
					}
					description += str;
				}

				if (text.contains("Timeline")) {
					String str = "";
					try {
						if (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
							str = element.nextElementSibling().text();
							List<String> dates = getDates(str);

							// the last date under timeline!
							publishDate = dates.get(dates.size() - 1);
							publishDate = UtilHelper.longDateFormat.format(dateFormat_yyyy_MM_dd.parse(publishDate));
						}
						// description += str;
					} catch (Exception e) {
						logger.error("Error parsing Timeline section at: " + sSourceURL);
					}
				}

			}

			for (String cveId : uniqueCves)
				vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cveId, platform, publishDate, lastModifiedDate, description, sourceDomainName));
		} catch (Exception e) {
			logger.error("An error occurred while parsing TalosIntelligence URL: " + sSourceURL);
		}

		return vulnerabilities;
	}

	protected List<String> getDates(String text) {
		List<String> dates = new ArrayList<>();
		Pattern cvePattern = Pattern.compile(regexDateFormatNumeric);
		Matcher cveMatcher = cvePattern.matcher(text);
		while (cveMatcher.find())
			dates.add(cveMatcher.group());

		return dates;
	}

}
