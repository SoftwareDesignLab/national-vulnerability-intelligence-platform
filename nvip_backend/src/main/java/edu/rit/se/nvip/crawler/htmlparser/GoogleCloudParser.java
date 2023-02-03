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

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.jsoup.nodes.Element;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.*;


/**

    Parse Google Cloud Support Bulletin

    (Currently unfinished but might want to use it for patchfinder)

    @author Andrew Pickard
 */


public class GoogleCloudParser extends AbstractCveParser implements CveParserInterface {

    private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public GoogleCloudParser(String domainName) {
		sourceDomainName = domainName;
	}


    @Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Document doc = Jsoup.parse(sCVEContentHTML);
        String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

        Pattern pattern = Pattern.compile(regexCVEID);

        Elements tables = doc.select("div.devsite-table-wrapper");

        for (Element table: tables) {
            
            Elements body = table.select("tbody").first().select("td");
            String description = body.get(0).text();
            Matcher matcher = pattern.matcher(description);

            /*if (matcher.find()) {

            }

            for (Element bodyCol: body) {
                
            }*/
        }

        return null;

    }

}