package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.ArrayList;
import java.util.List;

public class BoschSecurityParser extends AbstractCveParser{


    public BoschSecurityParser(String domainName) {
        sourceDomainName = domainName;
    }

    /**
     * Parse Bosch Security Advisory
     * (ex. https://psirt.bosch.com/security-advisories/bosch-sa-247053-bt.html)
     * @param sSourceURL
     * @param sCVEContentHTML
     * @return
     */
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<CompositeVulnerability> vulns = new ArrayList<>();



        return vulns;
    }
}
