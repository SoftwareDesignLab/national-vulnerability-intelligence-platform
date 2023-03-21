/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class AmpereRootParser extends AbstractCveParser {

    /**
     * Parse bulletin table in ampere product security page
     * @param rootDomain - amperecomputing.com/products/product-security
     */
    public AmpereRootParser(String rootDomain) { sourceDomainName = rootDomain; }

    /**
     * parse an individual vuln page and add useful info to vuln description
     * @param sSourceURL - url of individual page
     * @return - text to add to description
     */
    public String parseIndividualWebPage(String sSourceURL) {
        QuickCveCrawler qCrawler = new QuickCveCrawler();
        String html = qCrawler.getContentFromUrl(sSourceURL);
        Document doc = Jsoup.parse(html);
        StringBuilder info = new StringBuilder(" ");
        // if summary and if has next p tag, add it
        Element summaryHeader = doc.select("h3:contains(Summary)").first();
        if (summaryHeader != null) {
            Element summaryPara = summaryHeader.nextElementSibling();
            while (summaryPara != null && summaryPara.tagName().contains("p")) {
                info.append(summaryPara.text());
                summaryPara = summaryPara.nextElementSibling();
            }
        }
        // if problem statement and impact and if has next p tag, add it
        Element probStatementHeader = doc.select("h3:contains(Problem Statement)").first();
        if (probStatementHeader != null) {
            Element probPara = probStatementHeader.nextElementSibling();
            while (probPara != null && probPara.tagName().contains("p")) {
                info.append(" ").append(probPara.text());
                probPara = probPara.nextElementSibling();
            }
        }

        return info.toString();
    }

    /**
     * parse root ampere vuln web page table
     * @param sSourceURL - amperecomputing.com/products/product-security
     * @param sCVEContentHTML - parsed html of source url
     * @return - CVE list from bulletin table
     */
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        Element tableHeader = doc.select("thead:contains(Bulletin)").first();
        // get each row of table
        if (tableHeader == null) return vulnList;
        Element tableBody = tableHeader.nextElementSibling();
        if (tableBody == null) return vulnList;
        Elements rows = tableBody.children();
        for (Element row : rows) {
            String cveId = row.child(2).text();
            Element title = row.child(1).child(0);
            String description = title.text();
            description += parseIndividualWebPage(title.attr("href"));
            String publishDate = row.child(3).text();
            String lastUpdated = row.child(4).text();
            // iterative parse each link from table to gain more information

            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cveId, null, publishDate, lastUpdated, description, sourceDomainName
            ));
        }

        return vulnList;
    }
}
