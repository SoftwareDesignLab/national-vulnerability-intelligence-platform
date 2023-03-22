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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class MicrosoftParser extends AbstractCveParser {

    /**
     * Parse advisories listed to msrc.microsoft.com/update-guide/vulnerability
     * @param domainName - msrc domain
     */
    public MicrosoftParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // extract CVE ID from top of page above "Security Vulnerability"
        Element cve = doc.select("span.css-242:contains(CVE)").first();
        String cveId = Objects.requireNonNull(cve).text();

        // extract released and last updated dates
        Element dates = doc.select("p:contains(Released)").first();
        String[] dateSplit = Objects.requireNonNull(dates).text().split("Last updated: ");
        String publishDate = dateSplit[0].trim();
        String lastModifiedDate = dateSplit[1];
        publishDate = publishDate.split(": ")[1].trim();

        // lack of a description on these pages
        // instead title + FAQ will be extracted
        Element titleEl = doc.select("h1.ms-fontWeight-semibold").first();
        String title = Objects.requireNonNull(titleEl).text();
        Element faqTitle = doc.select("h2:contains(FAQ)").first();
        String faq = Objects.requireNonNull(Objects.requireNonNull(faqTitle).nextElementSibling()).text();

        vulnList.add(new CompositeVulnerability(
           0, sSourceURL, cveId, null, publishDate, lastModifiedDate, title + faq, sourceDomainName
        ));

        return vulnList;
    }
}
