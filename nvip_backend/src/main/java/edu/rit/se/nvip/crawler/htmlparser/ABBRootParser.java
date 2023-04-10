package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.util.ArrayList;
import java.util.List;

public class ABBRootParser extends AbstractCveParser {

    /**
     * Parse root advisories page listed to global.abb/group/en/technology/cyber-security/alerts-and-notifications
     * Individual pages links to pdf files, download and parse those
     * @param domainName - global abb domain
     */
    public ABBRootParser(String domainName) {
        sourceDomainName = domainName;
    }

    private void downloadPDF(String pdfURL) {

    }

    private void parsePDF(String pdfURL) {

    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        //

        return vulnList;
    }
}
