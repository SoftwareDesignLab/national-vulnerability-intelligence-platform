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
	
	public AnquankeParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();

		return vulnerabilities;
	}

	/**
	 * Parse pages like: https://www.anquanke.com/post/id/210200
	 *
	 * TODO: 1/18/23 --> Change this to a parseWebPage method (if we still want to use it)
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
			/**
			 * Ignore for now! The content is in Chinese
			 */

			for (String cveId : uniqueCves)
				vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cveId, platform, publishDate, lastModifiedDate, description, null));
		} catch (Exception e) {
			logger.error("An error occurred while parsing Anquanke URL: " + sSourceURL);
		}

		return vulnerabilities;
	}
}
