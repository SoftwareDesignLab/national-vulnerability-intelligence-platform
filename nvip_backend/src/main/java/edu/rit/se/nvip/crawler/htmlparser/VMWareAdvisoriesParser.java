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

import edu.rit.se.nvip.model.AffectedRelease;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.productnameextractor.CpeLookUp;
import edu.rit.se.nvip.utils.UtilHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parse CVEs at VMWare advisory
 * 
 * @author axoeec
 *
 */
public class VMWareAdvisoriesParser extends AbstractCveParser implements CveParserInterface {
	
	public VMWareAdvisoriesParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Date updateDate = new Date();
		String updateDateString = UtilHelper.longDateFormat.format(updateDate);

		Pattern datePattern = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
		String publishDate = null;

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.isEmpty())
			return vulns;

		Document doc = Jsoup.parse(sCVEContentHTML);

		Elements dates = doc.getElementsByAttributeValue("name", "date");
		if (dates.size() > 1)
			return vulns;

		Matcher dateMatcher = datePattern.matcher(dates.get(0).attr("content"));
		if (dateMatcher.find()) {
			try {
				publishDate = UtilHelper.longDateFormat.format(dateFormat.parse(dateMatcher.group()));
			} catch (ParseException e) {
				e.printStackTrace();
			}
		}

		Set<String> productStrings = new HashSet<>();

		// tables come with either the table tag, or the class rTable
		Elements tables = doc.getElementsByTag("table");
		tables.addAll(doc.getElementsByClass("rTable"));
		for (Element table : tables) {
			// adding all possible table rows
			Elements rows = table.getElementsByTag("tr");
			rows.addAll(table.getElementsByClass("rTableHeading"));
			rows.addAll(table.getElementsByClass("rTableRow"));
			List<Integer> versionCols = new ArrayList<>();

			for (int i = 0; i < rows.size(); i++) {
				Element row = rows.get(i);
				if (i == 0) {
					// identify columns with version info
					int j = 0;
					Elements tds = row.getElementsByTag("td");
					tds.addAll(row.getElementsByClass("rTableCell"));
					tds.addAll(row.getElementsByClass("rTableHead"));
					for (Element td : tds) {
						if (td.text().toLowerCase().contains("version"))
							versionCols.add(j);
						j++;
					}
				} else {

					String name = row.child(0).text();
					for (int index : versionCols) {
						Element versionNode = row.child(index);
						String version = "";
						// getting only text from textnodes, gets rid of spans
						for (Node child : versionNode.childNodes()) {
							if (child.getClass().equals(TextNode.class))
								version += child.toString().trim();
						}
						productStrings.add(name + " " + version);
					}
				}
			}
		}

		// Get Description
		Elements textElements = doc.getElementsByClass("paragraphText");
		String desc = "";
		for (Element paragraph : textElements) {
			Elements ps = paragraph.getElementsByTag("p");
			for (Element p : ps) {
				if (p.classNames().isEmpty())
					if (p.text().trim().equals("None."))
						continue;
				if (p.text().contains("https://"))
					continue;
				desc += p.text() + "\n";
			}
		}

		List<String> descriptionProducts = getPlatformVersions(desc);
		productStrings.addAll(descriptionProducts);

		Set<Product> products = new HashSet<>();

		List<AffectedRelease> affectedReleases = new ArrayList<>();
		CpeLookUp loader = CpeLookUp.getInstance();

		for (String p : productStrings) {
			Product curr = loader.productFromDomain(p);
			if (curr != null)
				products.add(curr);
		}

		for (Product p : products)
			affectedReleases.add(new AffectedRelease(p.getCpe(), publishDate, p.getVersion()));

		for (String cve : uniqueCves) {
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, updateDateString, desc, sourceDomainName);
			for (AffectedRelease a : affectedReleases) {
				vuln.addAffectedRelease(a);
			}
			vulns.add(vuln);
		}

		return vulns;
	}
}
