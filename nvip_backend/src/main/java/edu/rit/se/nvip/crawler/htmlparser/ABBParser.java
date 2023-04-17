package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ABBParser extends AbstractCveParser {

    /**
     * Parse root advisories page listed to global.abb/group/en/technology/cyber-security/alerts-and-notifications
     * Individual pages links to pdf files, download and parse those
     * @param domainName - global abb domain
     */
    public ABBParser(String domainName) {
        sourceDomainName = domainName;
    }

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
            // get CVE id from String
            Set<String> cves = getCVEs(pdfString);

            // date sometimes differs in location but there is always 1 date in the form yyyy-mm-dd
            String date = "";
            Pattern cvePattern = Pattern.compile(regexDateYearMonthDay);
            Matcher cveMatcher = cvePattern.matcher(pdfString);
            if (cveMatcher.find())
                date = cveMatcher.group();

            // get description from Summary section
            String description = "";
            pdfString = pdfString.replace("\r", "");
            String[] summarySplit = pdfString.split("Summary \n");
            // get the entire string as description by default - some old ones don't have a different formats
            if (summarySplit.length > 1) {
                String summary = summarySplit[1];
                String[] endSplit = summary.split("© Copyright");
                description = endSplit[0];
            } else
                description = pdfString;

            // usually just 1 but we will loop over the set just to be sure
            for (String cve : cves)
                vulnList.add(new CompositeVulnerability(
                        0, sSourceURL, cve, null, date, date, description, sourceDomainName
                ));
        }
        return vulnList;
    }
}
