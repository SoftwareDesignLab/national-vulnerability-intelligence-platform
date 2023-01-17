/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.cnnvd;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.select.Elements;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CnnvdVulnerability;

/**
 * 
 * Cnnvd parser
 * 
 * @author axoeec
 *
 */
public class CnnvdCveParser {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private Pattern patternUrl;

	public CnnvdCveParser() {
		String regexForLink = "\\(?\\b(http://|www[.])[-A-Za-z0-9+&amp;@#/%?=~_()|!:,.;]*[-A-Za-z0-9+&amp;@#/%=~_()|]";
		patternUrl = Pattern.compile(regexForLink);

	}

	/**
	 * get CNNVD full URLs from a page html
	 * 
	 * @param html
	 * @return
	 */
	public List<String> getCveUrlListFromPage(String html) {
		List<String> cveUrlList = new ArrayList<>();
		/**
		 * append this base URL to each CNNVD item:
		 * 
		 * "web/xxk/ldxqById.tag?CNNVD=CNNVD-202003-1585"
		 */
		String pageUrl = "http://www.cnnvd.org.cn/";

		Document document = Jsoup.parse(html);
		Elements cveItemList = document.select("div[class=list_list]").select("li");
		for (Element item : cveItemList) {
			String link = item.select("a").get(0).attr("href");
			cveUrlList.add(pageUrl + link);
		}

		return cveUrlList;
	}

	/**
	 * Pick CVE details from the page
	 * 
	 * @param html
	 * @return
	 */
	public CnnvdVulnerability getCveDetailsFromPage(String html) {
		// this a content from a URL stg like:
		// http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202003-1555

		CnnvdVulnerability vuln = new CnnvdVulnerability();

		Map<String, String> dictionary = getBasicDictionary();

		Document document = Jsoup.parse(html);

		Elements cveItemList = document.select("div[class=detail_xq w770]").select("li");
		for (int attributeIndex = 0; attributeIndex < cveItemList.size(); attributeIndex++) {
			Element item = cveItemList.get(attributeIndex);
			String[] attr;

			attr = item.text().split("ï¼š");
			if (attr.length == 1)
				continue;

			String value = attr[1].trim();
			if (attributeIndex == 0)
				vuln.setChinaCveId(value);
			else if (attributeIndex == 1)
				vuln.setHazardLevel(dictionary.get(value));
			else if (attributeIndex == 2)
				vuln.setCVEID(value);
			else if (attributeIndex == 3)
				vuln.setVulnerabilityType(dictionary.get(value));
			else if (attributeIndex == 4)
				vuln.setPublishDate(value);
			else if (attributeIndex == 5)
				vuln.setThreatType(dictionary.get(value));
			else if (attributeIndex == 6)
				vuln.setUpdateDate(value);
			else if (attributeIndex == 7)
				vuln.setFactory(value);
			else if (attributeIndex == 8)
				vuln.addVulnerabilitySource(value);
		}
		return vuln;
	}

	/**
	 * Translation of simple labels
	 * 
	 * @return
	 */
	private Map<String, String> getBasicDictionary() {
		Map<String, String> dict = new HashMap<>();
		dict.put("CNNVDç¼–å�·", "CNNVD");
		dict.put("CVEç¼–å�·", "CVE");
		dict.put("å�‘å¸ƒæ—¶é—´", "Published");
		dict.put("æ›´æ–°æ—¶é—´", "Updated");
		dict.put("æ¼�æ´žæ�¥æº�", "Source");
		dict.put("å�±å®³ç­‰çº§", "Hazard-level");
		dict.put("æ¼�æ´žç±»åž‹", "Type");
		dict.put("å¨�èƒ�ç±»åž‹", "Threat-type");
		dict.put("åŽ‚\\xa0\\xa0\\xa0\\xa0\\xa0\\xa0\\xa0å•†", "Manufacturer");
		dict.put("ä¸­å�±", "Medium");
		dict.put("å…¶ä»–", "Other");
		dict.put("é«˜å�±", "High Risk");
		dict.put("è¶…å�±", "Super Danger");
		dict.put("ä½Žå�±", "Low Risk");

		return dict;
	}

	/**
	 * get reference (source) URLs from a CNNVD page
	 * 
	 * @param html
	 * @return
	 */
	public List<String> getCveReferencesFromPage(String html) {
		// this a content from a URL stg like:
		// http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202003-1555

		String regexUrl = "((http?|https|ftp|file)://)?((W|w){3}.)?[a-zA-Z0-9]+\\.[a-zA-Z]+";

		List<String> list = new ArrayList<>();

		Document document = Jsoup.parse(html, "", Parser.xmlParser());
		try {
			Elements itemListMain = document.select("div[class=d_ldjj m_t_20]");
			Element relatedRefUrlElement = itemListMain.get(1); // this is the <div> that includes references
			Elements pElements = relatedRefUrlElement.select("p"); // get all <p> tags within the ref div

			if (pElements.size() == 1) {
				// all URLs in the same p tag?
				return matchURLsFromText(pElements.get(0).text());
			}

			// <p
			// style="text-indent:2em;width:890px;"class="ckwz">é“¾æŽ¥:http://www.securityfocus.com/bid/1</p>
			for (int index = 0; index < pElements.size(); index++) {
				String text = pElements.get(index).text();
				int beginIndex = text.indexOf("http");
				if (beginIndex >= 0) {
					String link = text.substring(beginIndex);
					list.add(link);
				}
			}
		} catch (Exception e) {
			logger.error("Error while getting reference URLs: " + e + ", HTML Content: " + html);
		}
		return list;
	}

	/**
	 * get one or more URLs from a given text
	 * 
	 * @param text
	 * @return
	 */
	public List<String> matchURLsFromText(String text) {
		List<String> list = new ArrayList<>();
		Matcher matcher = patternUrl.matcher(text);

		while (matcher.find())
			list.add(matcher.group(0));

		return list;
	}
}
