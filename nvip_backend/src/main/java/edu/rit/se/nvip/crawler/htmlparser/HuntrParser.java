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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class HuntrParser extends AbstractCveParser {

    /**
     * Parse pages listed to huntr.dev/bounties/hacktivity
     * @param domainName - huntr domain
     */
    public HuntrParser(String domainName) { sourceDomainName = domainName; }

    private String agoToDate(String timeStamp) {
        LocalDate today = LocalDate.now();
        String[] timeSplit = timeStamp.split(" ");
        List<String> todayStrings = Arrays.asList("seconds", "minutes", "hours");
        // if shorter than a day recently updated
        if (todayStrings.contains(timeSplit[1])) return today.toString();
        // otherwise compute how many days we need to go back from today
        int amount;
        if (Objects.equals(timeSplit[0], "a")) amount = 1;
        else amount = Integer.parseInt(timeSplit[0]);
        // estimate 1 day, 30 days for a month, and 365 days for a year
        int minusDays = timeSplit[1].contains("day") ? 1 :
                timeSplit[1].contains("month") ? 30 :
                        timeSplit[1].contains("year") ? 365 : 0;
        // if we are unable to correctly parse "time ago" string, return null and
        // refer back to the published date string
        int mult = amount * minusDays;
        if (mult == 0) return null;
        else return today.minusDays(mult).toString();
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVE ID from actions and stats pane on the right hand side
        Element stats = doc.select("div#actions-and-stats").first();
        String statsText = stats != null ? stats.text() : "";
        if (!statsText.contains("CVE")) return vulnList;
        Elements cveEl = stats.children().select("div:contains(CVE-)");
        String cveId = cveEl.get(2).text().split("\\(")[0].trim();

        // get description text under h1 Description header
        Element descHeader = doc.select("h1:contains(Description)").first();
        Element descriptionNext = descHeader != null ? descHeader.nextElementSibling() : null;
        String description = descriptionNext != null ? descriptionNext.text() : "";

        // get publish date from 'Reported on ____'
        Element reportedOn = doc.select("p:contains(Reported on)").first();
        Element reportedDateEl = reportedOn != null ? reportedOn.nextElementSibling() : null;
        // create a formatter to parse date
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd uuuu");
        // get rid of any date ordinals for parsing using regex
        String reportedDate = LocalDate
                .parse(Objects.requireNonNull(reportedDateEl).text().replaceAll("(?<=\\d)(st|nd|rd|th)", ""), formatter)
                .toString();
        // get last modified date computed from the most recent message's timestamp
        Element messageContainer = doc.select("div#messages-container").first();
        // get the last message box in messageContainer
        Element lastMessage = Objects.requireNonNull(messageContainer).children().select("div#message-box").last();
        Element timeStampEl = Objects.requireNonNull(lastMessage).children().select("span:contains(ago)").first();
        String timeStamp = Objects.requireNonNull(timeStampEl).text();

        String lastModified = agoToDate(timeStamp);
        if (lastModified == null) lastModified = reportedDate;

        vulnList.add(new CompositeVulnerability(
           0, sSourceURL, cveId, null, reportedDate, lastModified, description, sourceDomainName
        ));

        return vulnList;
    }
}
