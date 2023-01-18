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

import java.text.ParseException;
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
 * Parse SecurityTracker CVEs
 * 
 * @author axoeec
 *
 */
public class SecurityTrackerParser extends AbstractCveParser implements CveParserInterface {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	
	public SecurityTrackerParser(String domainName) {
		sourceDomainName = domainName;
	}

	String[] keywords = new String[] { "Description", "Impact", "Solution" };

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<CompositeVulnerability>();
		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

		/**
		 * page contains CVE?
		 */
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return vulnerabilities;

		/**
		 * Start parsing
		 */
		Document document = Jsoup.parse(sCVEContentHTML);

		String description = "";
		String publishDate = null;
		String platform = null;

		// Find the right table

		Elements tables = document.select("table");
		int tableIndex = 0;
		while (tableIndex < tables.size()) {
			Element table = tables.get(tableIndex);
			String sTableContent = table.text();
			if (getCVEs(sTableContent).size() == 0) {
				tableIndex++;
				continue;
			}

			tableIndex++;

			// we found the table, get data from it!
			Elements elementList = table.select("td");
			int elementIndex = 0;
			while (elementIndex < elementList.size()) {
				Element element = elementList.get(elementIndex);
				String elementText = element.text();

				while (element.childrenSize() > 0) {
					element = element.child(0);
					elementText = element.text();

					if (elementText.contains(keywords[0]) || elementText.contains(keywords[1]) || elementText.contains(keywords[2])) {
						if (!description.contains(elementText))
							description += (elementText + "\n");
						break;
					}

					if (elementText.contains("Version(s):")) {
						// Version(s): Prior to X.Y.Z
						platform = elementText.replace("Version(s):", "").trim();
						break;
					}

					if (elementText.contains("Date:")) {
						// Date: May 8 2018
						String sDate = null;
						try {
							sDate = getDates(elementText).get(0);
							publishDate = UtilHelper.longDateFormat.format(dateFormat_MMMddYYYY.parse(sDate));
							break;
						} catch (ParseException e) {
							logger.error("Error parsing date: " + sDate + " at " + sSourceURL);
						}
					}
				}
				elementIndex++;
			}

		}

		for (String cve : uniqueCves)
			vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cve, platform, publishDate, lastModifiedDate, description, sourceDomainName));

		return vulnerabilities;
	}

	protected List<String> getDates(String text) {
		String regexDateFormat = "([a-zA-Z]+ [0-9]+ [0-9]+)";
		List<String> dates = new ArrayList<>();
		Pattern cvePattern = Pattern.compile(regexDateFormat);
		Matcher cveMatcher = cvePattern.matcher(text);
		while (cveMatcher.find())
			dates.add(cveMatcher.group());

		return dates;
	}

}
