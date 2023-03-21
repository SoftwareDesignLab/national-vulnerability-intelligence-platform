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
import java.util.Objects;

public class TrendMicroParser extends AbstractCveParser {

    /**
     * Parse advisories listed to TrendMicro.com/vinfo/us/threat-encyclopedia/vulnerability
     * Specifically 'Security Update Overview' pages from Zero Day Initiative
     * @param domainName - zero day initiative domain (zerodayinitative.com/.....)
     */
    public TrendMicroParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get date - blog posts refer to these overviews as Patch Tuesday
        // so expect this date to always be the second Tuesday of a given month
        Element dateEl = Objects.requireNonNull(doc.select("h1.title").first()).nextElementSibling();
        String date = Objects.requireNonNull(dateEl).text().split("\\|")[0].trim();

        // get the big table element containing all the CVEs
        Elements tableEls = doc.select("table");
        Element table = tableEls.first();
        if (table == null) return null;
        Element tableBody = table.children().select("tbody").first();
        Elements rows = Objects.requireNonNull(tableBody). children();
        for (Element row : rows) {
            String text = row.text();
            if (text.contains("CVE-")) {
                // get each block inside the row
                Elements rowTDs = row.children().select("td");
                // cve box
                Element cveTD = rowTDs.first();
                String cveId = Objects.requireNonNull(cveTD).text();
                // "Title" box we will use for description
                Element descTD = cveTD.nextElementSibling();
                String description = Objects.requireNonNull(descTD).text();
                vulnList.add(new CompositeVulnerability(
                   0, sSourceURL, cveId, null, date, date, description, sourceDomainName
                ));
            }
        }
        return vulnList;
    }
}
