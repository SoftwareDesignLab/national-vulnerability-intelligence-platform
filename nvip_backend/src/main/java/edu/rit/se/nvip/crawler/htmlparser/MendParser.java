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

import java.util.ArrayList;
import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class MendParser extends AbstractCveParser {

    /**
     * Parse advisories listed to mend.io/vulnerability-database
     * Ex: <a href="https://www.mend.io/vulnerability-database/CVE-2023-22736">...</a>
     * @param domainName
     */
    public MendParser(String domainName) {
        sourceDomainName = domainName;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);
        // get the CVE ID in the h1 title
        Elements cveIdEl = doc.select("h1:contains(CVE-)");
        if (cveIdEl.size() == 0)
            return vulnList;
        String cveId = cveIdEl.get(0).text();
        // left hand side text is under 'single-vuln-desc' class
        Element dateAndDesc = doc.getElementsByClass("single-vuln-desc").get(0);
        // extract date, the first child h4 of vuln desc div
        Elements dateEl =  dateAndDesc.select("h4:contains(Date:)");
        String publishedDate = dateEl.get(0).text().split(": ")[1].trim();
        // grab the description, the p tag second child
        Elements descEl = dateAndDesc.select("p");
        String description = dateAndDesc.select("p").get(0).text();

        vulnList.add(new CompositeVulnerability(0, sSourceURL, cveId, null, publishedDate, publishedDate, description, sourceDomainName));

        return vulnList;
    }
}
