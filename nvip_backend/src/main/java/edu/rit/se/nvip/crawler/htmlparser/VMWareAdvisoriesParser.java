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

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;

/**
 * Parse CVEs at VMWare advisory
 * TODO: Extract CVSS Scores from descriptions
 * @author axoeec, aep7128
 *
 */
public class VMWareAdvisoriesParser extends AbstractCveParser  {
	
	public VMWareAdvisoriesParser(String domainName) {
		sourceDomainName = domainName;
	}

	/**
	 * Parse VMWare Security Advisory Pages
	 * (ex. https://www.vmware.com/security/advisories/VMSA-2023-0003.html)
	 * (ex. https://www.vmware.com/security/advisories/VMSA-2023-0001.html)
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.isEmpty())
			return vulns;

		Document doc = Jsoup.parse(sCVEContentHTML);

		ArrayList<Element> headers = doc.getElementsByClass("sa-row-group");

		String publishDate = headers.get(2).getElementsByTag("span").text();
		String updatedDate = headers.get(3).getElementsByTag("span").text().substring(0, 10);
		String[] cveIds = headers.get(4).getElementsByTag("span").text().trim().split(",");
		String currentCVE = "";

		/*
		Iterate through each header element and check the following
			1.) If the header contains a CVEID, assign it as current CVE
		   	2.) If the header has "Description" in it, pull the text from the sibling element
		   	and store the current cve with that description
		 */
		Elements items = doc.getElementsByClass("secadvheading");

		for (Element heading: items) {

			String description = "";

			for (String cveId: cveIds) {
				if (heading.text().contains(cveId.trim())) {

					currentCVE = cveId.trim();
					Element sibling = heading.nextElementSibling();

					if (Objects.requireNonNull(sibling).text().equals("Description")) {
						description = Objects.requireNonNull(sibling.nextElementSibling()).text();
						vulns.add(new CompositeVulnerability(0, sSourceURL, currentCVE, null, publishDate, updatedDate, description, sourceDomainName));
					} else if (Objects.requireNonNull(sibling).text().length() > 30) {
						vulns.add(new CompositeVulnerability(0, sSourceURL, currentCVE, null, publishDate, updatedDate, sibling.text(), sourceDomainName));
					}
				}
			}


		}

		return vulns;
	}
}
