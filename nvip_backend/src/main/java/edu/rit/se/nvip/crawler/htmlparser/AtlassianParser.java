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
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class AtlassianParser extends AbstractCveParser {

    private final List<CompositeVulnerability> vulnList = new ArrayList<>();
    private ArrayList<String> cvesOnPage = new ArrayList<>();
    private String lastModifiedDate;
    private String publishDate;

    /**
     * Parse advisories listed to atlassian.com/trust/security/advisories
     * Ex: <a href="https://confluence.atlassian.com/doc/confluence-security-advisory-2019-12-18-982324349.html">...</a>
     * @param domainName - atlassian domain name
     */
    public AtlassianParser(String domainName) {
        sourceDomainName = domainName;
    }

    /**
     * take in page table element containing release date, parse, output release date string
     * @param rowElement - <td></td> element of date
     * @return - date in String form
     */
    private String extractReleaseDate(Element rowElement) {

        // this will contain a <time> element that has the date
        // and a text portion containing the time
        Element dateElement = rowElement.child(0);
        // trim off hour differential portion in parentheses next to the time
        return dateElement.text().split("\\(")[0].trim();
    }

    /**
     * take in page table element containing list of CVEs, parse, output list of CVEs on page
     * @param rowElement - <td></td> element of CVEs in table
     * @return - Each CVE in string form, in a list
     */
    private ArrayList<String> extractPageCves(Element rowElement) {
        String cveStrings = rowElement.text();
        return new ArrayList<>(Arrays.asList(cveStrings.split(" ")));
    }

    /**
     * given a header, get all children elements below it, append to a desc string
     * @param headers - each description / CVE header
     * @param sSourceURL - url of site
     */
    private void extractDescUnderHeaders(Elements headers, String sSourceURL) {
        for (int i = 0; i < headers.size(); i++) {
            Element header = headers.get(i);
            StringBuilder description = new StringBuilder();
            Element next = header.nextElementSibling();
            while (!Objects.requireNonNull(next).tagName().contains("h")) {
                description.append(next.text());
                next = next.nextElementSibling();
            }
            vulnList.add(new CompositeVulnerability(
                    0,
                    sSourceURL,
                    cvesOnPage.get(i),
                    "atlassian",
                    publishDate,
                    lastModifiedDate,
                    description.toString(),
                    sourceDomainName
            ));
        }
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        Document doc = Jsoup.parse(sCVEContentHTML);

        // the top-most table, containing info on summary, release date, affected products, and CVE id's
        Element table = doc.getElementsByClass("wrapped confluenceTable").get(0);
        // get the rows of the table
        Elements rows = table.children().get(1).children();

        // take the "Last modified on" date at the bottom
        Elements lastModifiedEl = doc.getElementsByClass("content-page-last-modified-date");
        lastModifiedDate = lastModifiedEl.text().split("on ")[1];

        for (Element row : rows) {
            String rowTitleElement = row.child(0).text();
            Element rowDataElement = row.child(1);

            // advisory release date in table is our vulns publishDate
            if (rowTitleElement.contains("Advisory Release Date"))
                publishDate = extractReleaseDate(rowDataElement);

            // cves mentioned on this advisories page are located in CVE ID(s) row
            if (rowTitleElement.contains("CVE"))
                cvesOnPage = extractPageCves(rowDataElement);
        }

        // get all description headers
        Elements headers = doc.select("h3:contains(Description),h4:contains(Description)");
        // get possible h1s, h2s or h3s foreach CVE on page
        Elements cveHeaders = doc.select("h1:contains(CVE-), h2:contains(CVE-), h3:contains(CVE-)");
        // remove first one because it's the title of the page
        cveHeaders.remove(0);

        // if description headers size > 0 assign desc headers
        if (headers.size() > 0) {
            extractDescUnderHeaders(headers, sSourceURL);
        }
        // if no explicitly defined "Description", take the summary under CVE header
        else if (cveHeaders.size() > 0 ) {
            extractDescUnderHeaders(cveHeaders, sSourceURL);
        }
        // if no description header or CVE headers
        // take the "Summary of Vulnerability" section
        else {
            Element summary = doc.select("h1:contains(Summary of ), h2:contains(Summary of ), h3:contains(Summary of )").get(0);
            StringBuilder description = new StringBuilder();
            Element next = summary.nextElementSibling();
            while (!Objects.requireNonNull(next).tagName().contains("h")) {
                description.append(next.text());
                next = next.nextElementSibling();
            }
            for (String cve : cvesOnPage) {
                vulnList.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, lastModifiedDate, description.toString(), sourceDomainName));
            }
        }

        return vulnList;
    }

}