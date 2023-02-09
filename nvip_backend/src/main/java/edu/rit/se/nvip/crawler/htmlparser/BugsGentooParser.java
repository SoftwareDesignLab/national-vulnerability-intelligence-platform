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
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Gentoo Linux Bug Advisory
 * @author axoeec, aep7128
 *
 * TODO: ADD GENTOO SECURITY IN PRODUCTS
 * TODO: use this for extracting patches from this source
 * TODO: Update model to add Patches to composite Vulnerabilities
 */
public class BugsGentooParser extends AbstractCveParser  {
	
	public BugsGentooParser(String domainName) {
		sourceDomainName = domainName;
	}

	/**
	 * Parse Method for Gentoo Bug Pages
	 * (ex. https://bugs.gentoo.org/600624)
	 * (ex. https://bugs.gentoo.org/890865)
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);

		if (uniqueCves.size() == 0)
			return vulns;

		String publishDate;
		String lastModified;

		Document doc = Jsoup.parse(sCVEContentHTML);

		publishDate = Objects.requireNonNull(doc.getElementById("bz_show_bug_column_2")).
				getElementsByTag("table").get(0).getElementsByTag("tr").get(0).
				getElementsByTag("td").get(0).text().substring(0, 20);

		lastModified = Objects.requireNonNull(doc.getElementById("bz_show_bug_column_2")).
				getElementsByTag("table").get(0).getElementsByTag("tr").get(1).
				getElementsByTag("td").get(0).text().substring(0, 20);

		String[] cves = Objects.requireNonNull(doc.getElementById("alias_nonedit_display")).text().split(",");
		Elements descs = doc.getElementsByClass("bz_first_comment");

		if (descs.size() == 1) {

			Pattern pattern;
			Matcher matcher;
			ArrayList<String> textItems = new ArrayList<>();

			if (cves.length == 1) {
				textItems.add(Jsoup.parse(descs.get(0).getElementsByClass("bz_comment_text").get(0).html()).text());
				pattern = Pattern.compile(regexCVEID);
				matcher = pattern.matcher(cves[0]);

				if (matcher.find()) {
					vulns.add(new CompositeVulnerability(0, sSourceURL, cves[0], null, publishDate, lastModified, textItems.get(0), sourceDomainName));
				}

			} else {
				textItems.addAll(Arrays.asList(Jsoup.parse(descs.get(0).html()).text().split("\n")));
				for (int i=0; i<textItems.size(); i++) {

					pattern = Pattern.compile(regexCVEID);
					matcher = pattern.matcher(textItems.get(i));
					int k = 0;

					if (matcher.find()) {
						String cveId = matcher.group();
						String commentDescription = null;
						String patch = null;

						i += 2;

						if (textItems.get(i).length() >= 20) {
							commentDescription = textItems.get(i).trim();
						} else {
							k += 2;
						}

						/*
						For Patches

						pattern = Pattern.compile("(Patch:|patch:) ");
						matcher = pattern.matcher(textItems[++i]);

						if (matcher.matches()) {
							patch = textItems[i].replace("Patch:", "").replace("patch:", "");
						} else {
							k++;
						}*/

						vulns.add(new CompositeVulnerability(0, sSourceURL, cveId, null, publishDate, lastModified, commentDescription, sourceDomainName));
					}
					i -= k;
				}
			}

		}



		return vulns;
	}
}
