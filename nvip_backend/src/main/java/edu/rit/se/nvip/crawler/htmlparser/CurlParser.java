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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CurlParser extends AbstractCveParser {

    private final SimpleDateFormat sdf_out = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

    public CurlParser(String domainName) {
        sourceDomainName = domainName;
    }
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        Document doc = Jsoup.parse(sCVEContentHTML);
        Set<String> cves = new HashSet<>();
        List<CompositeVulnerability> retVal = new ArrayList<>();

        boolean inDescription = false;
        boolean inTimeline = false;
        StringBuilder descriptionBuilder = new StringBuilder();
        StringBuilder timelineBuilder = new StringBuilder();
        String date = "";
        Element content = doc.selectFirst("div.contents");
        if (content == null) return retVal;
        for (Element e : content.children()) {
            if (e.tagName().equals("h1")) {
                cves = getCVEs(e.text());
                if (e.nextElementSibling() != null)
                    date = parseDateFromAdvisoryLine(e.nextElementSibling().text());
            }
            if (e.tagName().equals("h2")) {
                if (e.id().contains("vulnerability")) {
                    inDescription = true;
                    continue;
                }
                if (inDescription && e.id().contains("info")) {
                    descriptionBuilder.append("\n");
                    continue;
                }
                if (e.id().contains("affected-versions")) {
                    inDescription = false;
                    continue;
                }
                if (e.id().contains("timeline")) {
                    inTimeline = true;
                    continue;
                }
                if (e.id().contains("credits")) {
                    inTimeline = false;
                    continue;
                }
            }
            if (inDescription && e.tagName().equals("p")) {
                descriptionBuilder.append(e.text());
            }
            if (inTimeline && e.tagName().equals("p")) {
                timelineBuilder.append(e.text());
            }
        }
        // this means we didn't find a date below the title, so we'll use what's in the Timeline section
        if (date.isEmpty()) {
            date = parseDateFromTimelineSection(timelineBuilder.toString());
        }
        // this means we didn't find one in the title, so we'll grab anything on the page
        if (cves.size() == 0) {
            cves = getCVEs(doc.text());
            if (cves.size() == 0) return retVal;
        }

        for (String cve : cves) {
            retVal.add(new CompositeVulnerability(
                    0,
                    sSourceURL,
                    cve,
                    "curl",
                    date,
                    date,
                    descriptionBuilder.toString(),
                    sourceDomainName
            ));
        }

        return retVal;
    }

    private String parseDateFromTimelineSection(String body) {
        SimpleDateFormat sdf_in = new SimpleDateFormat("MMMM dd, yyyy");
        Pattern pattern = Pattern.compile("\\b\\p{Lu}\\p{L}+ \\d{1,2}, \\d{4}\\b");
        Matcher matcher = pattern.matcher(body);
        List<Date> dates = new ArrayList<>();
        /** There should be 3 dates. First the date the issue was reported to curl, next the date curl contacted
         *  distros@openwall, then the date a new libcurl version was released fixing the issue.
         **/
        while (matcher.find()) {
            String match = matcher.group();
            try {
                Date date = sdf_in.parse(match);
                dates.add(date);
            } catch (ParseException ignored) {}
        }
        if (dates.size() == 0) {
            return "";
        }
        Date toReturn = null;
        if (dates.size() == 1) {
            toReturn = dates.get(0);
        }
        if (dates.size() >= 2) {
            toReturn = dates.get(1);
        }
        return sdf_out.format(toReturn);
    }

    private String parseDateFromAdvisoryLine(String line) {
        // looking for dates like "February 15th 2023"
        SimpleDateFormat sdf_in = new SimpleDateFormat("MMMM dd yyyy");
        Pattern pattern = Pattern.compile("\\b\\p{Lu}\\p{Lower}+ \\d{1,2}(st|nd|rd|th)? \\d{4}\\b");
        Matcher matcher = pattern.matcher(line);
        Date date = null;
        if (matcher.find()) {
            String match = matcher.group();
            String[] pieces = match.split(" ");
            pieces[1] = pieces[1].replaceAll("[a-zA-Z]+", "");
            match = String.join(" ", pieces);
            try {
                date = sdf_in.parse(match);
                return sdf_out.format(date);
            } catch (ParseException ignored) {}
        }
        return "";
    }
}
