package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EatonParser extends AbstractCveParser {

    /**
     * parse advisories listed to eaton.com/us/en-us/company/news-insights/cybersecurity/security-notifications.html
     * @param domainName - eaton domain
     */
    public EatonParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);
        Elements pdfV = doc.select("pdf-viewer");
        if (pdfV.size() == 0) {
            return vulnList;
        }
        // the given url is a PDF link, download and parse it
        String pdfString = pdfToString(sSourceURL);
        if (pdfString != null && !pdfString.equals("")) {
            pdfString = pdfString.replace("\r", "");

            // get CVE id from String
            Set<String> cves = getCVEs(pdfString);

            String description = "";
            // for description get everything above 4. Remediation & Mitigation
            String[] vulnDetailsSplit = pdfString.split("Remediation & Mitigation");
            if (vulnDetailsSplit.length > 1) {
                description = vulnDetailsSplit[0];
            } else {
            // or just use the entire text
                description = pdfString;
            }

            // publish date get first date under 'Revision Control'
            String publishDate = new Date().toString();
            // last modified date get last date under 'Revision Control'
            String lastModifiedDate = publishDate;

            String[] revisionTableSplit = pdfString.split("Revision Control");
            if (revisionTableSplit.length > 1) {
                Set<String> uniqueDates = new HashSet<>();
                Pattern cvePattern = Pattern.compile(regexDateFormatNumeric);
                Matcher cveMatcher = cvePattern.matcher(revisionTableSplit[1]);
                while (cveMatcher.find())
                    uniqueDates.add(cveMatcher.group());
                publishDate = uniqueDates.stream().findFirst().get();
                lastModifiedDate = uniqueDates.stream().reduce((one, two) -> two).get();
            }
            for (String cve : cves)
                vulnList.add(new CompositeVulnerability(
                        0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
                ));

        }

        return vulnList;
    }
}
