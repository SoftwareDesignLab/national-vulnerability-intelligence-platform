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
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class JenkinsParser extends AbstractCveParser {

    /**
     * Parse advisories listed to jenkins.io/security/advisories
     * Ex: <a href="https://www.jenkins.io/security/advisory/2022-06-30/">...</a>
     * @param domainName - jenkins domain name
     */
    public JenkinsParser(String domainName) {
        sourceDomainName = domainName;
    }


    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // Get 'Jenkins Security Advisory YYYY-MM-DD' title
        String titleDate = doc.select("h1").text();
        String date = titleDate.split("Advisory")[1].trim();

        // get a list of all SECURITY lines to use to grab each CVE on the page
        Elements securityLines = doc.select("strong:contains(SECURITY-)");

        for (Element cveLine : securityLines) {
            // Extract CVE IDs from line
            List<String> lineSplit = Arrays.asList(cveLine.text().split(" "));
            List<String> cves = lineSplit.stream().filter(s -> s.contains("CVE-")).collect(Collectors.toList());
            // get description for given CVEs
            StringBuilder description = new StringBuilder();
            Element next = cveLine.nextElementSibling();
            while (!Objects.requireNonNull(next).tagName().contains("h")) {
                // add p to desc, given that it does not say:
                // "As of publication of this advisory, there is no fix. Learn why we announce this."
                if (next.className().contains("paragraph") && !next.text().contains("As of publication of this advisory, there is no fix. Learn why we announce this")) {
                    description.append(next.text());
                }
                next = next.nextElementSibling();
            }
            // finally assemble and add to vulnList
            for (String cve : cves)
                vulnList.add(new CompositeVulnerability(
                        0, sSourceURL, cve, null, date, date, description.toString(), sourceDomainName
                ));
        }



        return vulnList;
    }
}
