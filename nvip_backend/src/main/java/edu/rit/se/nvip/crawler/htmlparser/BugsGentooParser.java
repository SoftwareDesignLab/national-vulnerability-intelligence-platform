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
import org.jsoup.select.Elements;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author axoeec
 *
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
		List<String> commentedCVEs = new ArrayList<>();
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);

		if (uniqueCves.size() == 0)
			return vulns;

		String description = null;
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
			String[] textItems = Jsoup.parse(descs.get(0).getElementsByClass("bz_comment_text").get(0).html()).text().split("\n");

			if (cves.length == 1) {
				System.out.println(textItems[0]);
				pattern = Pattern.compile(regexCVEID);
				matcher = pattern.matcher(cves[0]);

				if (matcher.find()) {
					vulns.add(new CompositeVulnerability(0, sSourceURL, cves[0], null, publishDate, lastModified, textItems[0], sourceDomainName));
				}

			} else {
				for (int i=0; i<textItems.length; i++) {
					pattern = Pattern.compile(regexCVEID);
					matcher = pattern.matcher(textItems[i]);
					int k = 0;

					if (matcher.find()) {
						String cveId = matcher.group();
						String commentDescription = null;
						String patch = null;

						i += 2;

						if (textItems[i].length() >= 20) {
							commentDescription = textItems[i].trim();
						} else {
							k += 2;
						}

						/*
						TODO: use this for extracting patches from this source
						TODO: Update model to add Patches to composite Vulnerabilities

						pattern = Pattern.compile("(Patch:|patch:) ");
						matcher = pattern.matcher(textItems[++i]);

						if (matcher.matches()) {
							patch = textItems[i].replace("Patch:", "").replace("patch:", "");
						} else {
							k++;
						}*/

						vulns.add(new CompositeVulnerability(0, sSourceURL, cveId, null, publishDate, lastModified, commentDescription, sourceDomainName));
						commentedCVEs.add(cveId);
					}
					i -= k;
				}
			}

		}

		// TODO ADD GENTOO SECURITY IN PRODUCTS

		/*for (String cve : uniqueCves) {
			if (!commentedCVEs.contains(cve)) {
				vulns.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, lastModified, description, sourceDomainName));
			}
		}*/

		return vulns;
	}
}
