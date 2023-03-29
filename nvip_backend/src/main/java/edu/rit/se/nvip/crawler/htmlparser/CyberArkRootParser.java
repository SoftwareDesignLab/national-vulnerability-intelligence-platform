package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class CyberArkRootParser extends AbstractCveParser {

    /**
     * Parse bulletin table in ampere product security page
     * @param rootDomain - labs.cyberark.com/cyberark-labs-security-advisories/
     */
    public CyberArkRootParser(String rootDomain) { sourceDomainName = rootDomain; }

    /**
     * parse root CyberArk vuln web page table
     * @param sSourceURL - labs.cyberark.com/cyberark-labs-security-advisories/
     * @param sCVEContentHTML - parsed html of source url
     * @return - CVE list from bulletin table
     */
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);



        return vulnList;
    }

}
