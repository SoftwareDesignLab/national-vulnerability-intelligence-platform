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
import edu.rit.se.nvip.utils.UtilHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Parse CVEs from Security Gentoo
 * 
 * @author axoeec
 *
 */
public class SecurityGentooParser extends AbstractCveParser implements CveParserInterface {
	
	public SecurityGentooParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Document document = Jsoup.parse(sCVEContentHTML);

		String lastModified = UtilHelper.longDateFormat.format(new Date());

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);

		String description = null;
		String publishDate = null;

		DateFormat currFormat = new SimpleDateFormat("MMM dd, yyyy", Locale.ENGLISH);

		Elements strongs = document.getElementsByTag("strong");
		for (Element e : strongs) {
			if (e.text().equals("Release date")) {
				Element p = e.parent();
				for (Node n : p.childNodes()) {
					if (n instanceof TextNode && !((TextNode) n).text().trim().isEmpty()) {
						try {
							String text = ((TextNode) n).text().trim();
							publishDate = UtilHelper.longDateFormat.format(currFormat.parse(text));
						} catch (ParseException ex) {
						}
					}
				}
				break;
			}
		}

		Elements leads = document.getElementsByClass("lead");
		if (leads.size() == 1) {
			Element parent = leads.get(0).parent();
			Document leadDoc = Jsoup.parse(parent.html());
			Elements ps = leadDoc.getElementsByTag("p");
			description = "";
			for (Element p : ps) {
				description += p.text() + "  ";
			}
		}

		for (String cve : uniqueCves) {
			vulns.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, lastModified, description, sourceDomainName));
		}

		// TODO ADD PRODUCTS

		return vulns;
	}
}
