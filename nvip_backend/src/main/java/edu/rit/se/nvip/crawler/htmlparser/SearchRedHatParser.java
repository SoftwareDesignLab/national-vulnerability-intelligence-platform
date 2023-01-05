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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;


public class SearchRedHatParser extends AbstractCveParser implements CveParserInterface {

    private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	
	public SearchRedHatParser(String domainName) {
		sourceDomainName = domainName;
	}

    @Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);
        String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());
        Pattern pattern = Pattern.compile(regexCVEID);

        Elements cveResults = doc.select("a.list-result-Cve");

        try {
            for (Element cveResult: cveResults) {
                Document cvePage = Jsoup.connect(cveResult.select("a[href]").attr("href")).get();

                String cve = cveResult.select("h3").text();
                String description = cvePage.select("#cve-details-description").select("p").text();
                
                String lastModifiedText = cvePage.select("p.cve-last-modified").text();
                String[] parts = lastModifiedText.split(" ");
                String date = UtilHelper.longDateFormat.format(dateFormat_yyyy_MM_dd.parse(parts[0] + " " + parts[1] + " " + parts[2]));

                vulnerabilities.add(new CompositeVulnerability(0, sSourceURL, cve, null, date, lastModifiedDate, description, sourceDomainName));    
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        }
		
        return vulnerabilities;

	}

}