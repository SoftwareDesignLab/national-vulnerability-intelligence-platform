package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class ZeroDaysParser extends AbstractCveParser {

    /**
     * Parse advisories listed to cybersecurityworks.com/zerodays-vulnerability-list/
     * @param domainName - zero days domain
     */
    public ZeroDaysParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        Element rightColumn = doc.select("div.second-half").first();

        // get CVE Id from right column
        String cve = rightColumn.children().select("li:contains(CVE Number)").first().children().select("span").first().text();

        // get publish date from top row
        String publishDate = doc.select("h4:contains(Date)").first().nextElementSibling().text();

        // get description in p tags under Description header
        Element descHeader = doc.select("h3:contains(Description)").first();
//        String description = doc
        String description = "";
        Element nextDesc = descHeader.nextElementSibling();
        while (nextDesc != null) {
            description += nextDesc.text();
            nextDesc = nextDesc.nextElementSibling();
        }

        // get last modified date from last date in timeline on the bottom
        Element timeline = doc.select("div#timeline").last();
        Element lastDate = timeline.children().select("li").last();
        String lastModifiedDate = lastDate.children().select("strong").text().replace(":", "");

        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
        ));

        return vulnList;
    }
}
