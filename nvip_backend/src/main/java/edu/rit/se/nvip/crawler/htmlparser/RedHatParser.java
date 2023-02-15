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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import edu.rit.se.nvip.model.CompositeVulnerability;

/**
 * Web Parser for RedHat CVE Page
 * (ex. https://access.redhat.com/security/cve/cve-2023-25725)
 * @author aep7128
 */
public class RedHatParser extends AbstractCveParser  {

    public RedHatParser(String domainName) {
		sourceDomainName = domainName;
	}

    @Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnerabilities = new ArrayList<>();
        String pattern = "yyyy/MM/dd";
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);

        try {
            Document doc = Jsoup.parse(sCVEContentHTML);

            String cve = doc.select("h1.headline").text();
            String description = doc.select("#cve-details-description > div > div > pfe-markdown > p").text();

            String publishedDate = doc.select("p.cve-public-date > pfe-datetime > span").text().trim();

            String lastModifiedDate = doc.select("p.cve-last-modified > pfe-datetime > span").text().split("at")[0].trim();

            vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishedDate, lastModifiedDate, description, sourceDomainName));
        } catch (Exception e) {
            System.out.println(e);
        }
        return vulnerabilities;
	}

}