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

import com.google.common.collect.Iterables;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutodeskParser extends AbstractCveParser {

    public AutodeskParser(String domainName) {sourceDomainName = domainName;}
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<CompositeVulnerability> retVal = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);
        // get publish/revision dates from the summary info near the top
        Element pSummary = doc.select("p:contains(Original Publish)").last();
        if (pSummary == null) return retVal;
        String[] pText = pSummary.html().split("<br>");
        String pubDate = parseDateFromRow(pText[4]);
        String revDate = parseDateFromRow(pText[5]);

        // pull out info from summary/description fields. Some pages have essentially no information in the
        // description section so use the summary in that case.
        Elements h3s = doc.select("h3");
        String summary = "";
        for (Element h3 : h3s) {
            Element h3Next = h3.nextElementSibling();
            if (h3.text().equals("Summary")) {
                if (h3Next != null)
                    summary = h3Next.text();
            }
            if (h3.text().equals("Description") ) {
                if (h3Next == null) continue;
                Element descriptionParent = h3Next.nextElementSibling();
                if (descriptionParent == null) continue;
                // in this case the page just lists CVEs and the libraries they impact
                if (descriptionParent.tagName().equals("table")) {
                    Elements rows = descriptionParent.getElementsByTag("tr");
                    String leftLabel = rows.get(0).children().get(0).text();
                    for (int i = 1; i < rows.size(); i++) {
                        for (String cve : getCVEs(rows.get(i).html())) {
                            String des = String.format("%s\n%s: %s", summary, leftLabel, rows.get(i).children().get(0).text());
                            retVal.add(new CompositeVulnerability(
                                   0,
                                   sSourceURL,
                                   cve,
                                   "autodesk",
                                   revDate,
                                   pubDate,
                                   des,
                                   sourceDomainName
                            ));
                        }
                    }
                }
                // in this case the vulnerabilities are listed with a distinct description for each
                else if (descriptionParent.tagName().equals("ol")) {
                    for (Element li : descriptionParent.children()) {
                        int desStart = li.text().indexOf(":") + 2;
                        retVal.add(new CompositeVulnerability(
                                0,
                                sSourceURL,
                                Iterables.getOnlyElement(getCVEs(li.text())),
                                "autodesk",
                                revDate,
                                pubDate,
                                li.text().substring(desStart),
                                sourceDomainName
                        ));
                    }
                }
            }
        }
        return retVal;
    }

    private String parseDateFromRow(String row) {
        String out = "";
        Matcher matcher = Pattern.compile(regexDateFormatNumeric).matcher(row);
        SimpleDateFormat sdf_in = new SimpleDateFormat("MM/dd/yyyy");
        SimpleDateFormat sdf_out = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        try {
            if (matcher.find()) {
                out = sdf_out.format(sdf_in.parse(matcher.group()));
            }
        } catch (ParseException e) {
            out = "";
        }
        return out;
    }
}
