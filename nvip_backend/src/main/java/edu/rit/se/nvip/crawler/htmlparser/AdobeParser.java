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

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class AdobeParser extends AbstractCveParser {

    /**
     * Parse advisories listed to helpx.adobe.com/security.html
     * @param domainName - adobe domain
     */
    public AdobeParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        ArrayList<String> cves = new ArrayList<>();
        // get CVEs from Vulnerability details table
        Element vulnDetailsHeaderRow = doc.select("tr:contains(CVE Number)").first();
        if (vulnDetailsHeaderRow == null) return vulnList;
        Element next = vulnDetailsHeaderRow.nextElementSibling();
        while (next != null) {
            Elements cells = next.children().select("td");
            for (Element cell : cells)
                if (cell.text().contains("CVE-"))
                    cves.add(cell.text().trim());
            next = next.nextElementSibling();
        }

        if (cves.size() == 0) return vulnList;

        // get description under Summary header
        String description = "";
        Element summaryHeader = doc.select("h2:contains(Summary)").first();
        if (summaryHeader != null && summaryHeader.parent() != null) {
            summaryHeader = summaryHeader.parent().parent();
            if (summaryHeader != null) {
                Element summaryPara = summaryHeader.nextElementSibling();
                if (summaryPara != null)
                    description += summaryPara.text();
            }
        }

        // get publish date from cell in first table
        String publishDate = "";
        Element firstTableHeaderRow = doc.select("tr:contains(Date Published)").first();
        if (firstTableHeaderRow != null) {
            Element nextRow = firstTableHeaderRow.nextElementSibling();
            if (nextRow != null)
                publishDate = nextRow.child(1).text().trim();
        }

        // get updated date from top 'Last updated' text
        String lastModifiedDate = "";
        Element dateSpan = doc.select("span.publish-date").first();
        if (dateSpan != null)
            lastModifiedDate = dateSpan.text();
        else
            lastModifiedDate = publishDate;

        for (String cve : cves)
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
            ));

        return vulnList;
    }
}
