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
 * 
 * @author axoeec
 *
 */
public class BugsGentooParser extends AbstractCveParser  {
	
	public BugsGentooParser(String domainName) {
		sourceDomainName = domainName;
	}


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
				getElementsByClass("table").get(0).getElementsByClass("tr").get(0).
				getElementsByClass("td").get(0).text();

		lastModified = Objects.requireNonNull(doc.getElementById("bz_show_bug_column_2")).
				getElementsByClass("table").get(0).getElementsByClass("tr").get(1).
				getElementsByClass("td").get(0).text();

		Elements descs = doc.getElementsByClass("bz_first_comment");

		if (descs.size() == 1) {

			Pattern pattern;
			Document descDoc = Jsoup.parse(descs.get(0).html());
			Elements descText = descDoc.getElementsByClass("bz_comment_text");
			String[] textItems = descText.text().split("\n");

			Elements dateText = descDoc.getElementsByClass("bz_comment_time");
			DateFormat currentFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
			publishDate = dateText.text();

			try {
				publishDate = UtilHelper.longDateFormat.format(currentFormat.parse(publishDate));
			} catch (ParseException ignored) {
			}

			for (int i=0; i<textItems.length; i++) {
				pattern = Pattern.compile(regexCVEID);
				Matcher matcher = pattern.matcher(textItems[i]);
				int k = 0;

				if (matcher.matches()) {
					String cveId = matcher.group();
					String commentDescription = null;
					String patch = null;

					if (textItems[++i].length() >= 20) {
						commentDescription = textItems[i];
					} else {
						k++;
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

		for (String cve : uniqueCves) {
			if (!commentedCVEs.contains(cve)) {
				vulns.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, lastModified, description, sourceDomainName));
			}
		}

		// TODO ADD PRODUCTS

		return vulns;
	}
}
