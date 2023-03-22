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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class JVNParser extends AbstractCveParser {

    /**
     * Parse advisories listed to jvn.jp site
     * @param domainName - jvn domain
     */
    public JVNParser(String domainName) { sourceDomainName = domainName; }

    private ArrayList<String> getCVEIdsFromText(String[] text) {
        ArrayList<String> cves = new ArrayList<>();
        for (String str : text)
            if (str.matches(".*?\\bCVE-\\b.*?"))
                cves.add(str);
        return cves;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get published date and last updated from 'head-bar' component at top
        Element headBar = doc.select("div#head-bar-txt").first();
        String publishedDate = "";
        String lastUpdated = "";
        if (headBar != null) {
            String headBarText = headBar.text();
            String[] split = headBarText.split("最終更新日：");
            lastUpdated = split[1].trim().replaceAll("　", "");
            String[] pubSplit = split[0].split("公開日：");
            // weird spaces found in parsing text, make sure we get rid of those as well
            publishedDate = pubSplit[1].trim().replaceAll("　", "");
        }

        // headers are images with informative alt text
        // get potential cves in 'related document', 'detailed information' or
        // 'potential impact' sections

        // the table at the bottom of the page
        Element relatedDocument = doc.select("img[alt*=関連文書]").first();
        // sections 2-4 on the page - right below 'overview' and 'affected system'
        Element detailedInformation = doc.select("img[alt*=詳細情報]").first();
        Element potentialImpact = doc.select("img[alt*=想定される影響]").first();

        // safely retrieve CVE id's from bottom table
        List<String> cveTexts = new ArrayList<>();
        if (relatedDocument != null && relatedDocument.parent() != null) {
            Element boxParent = relatedDocument.parent().parent();
            if (boxParent != null) {
                Elements potentialCves = boxParent.children().select("a:contains(CVE-)");
                cveTexts = potentialCves.eachText();
            }
        }

        // safely retrieve description texts
        String detailedInformationText = "";
        String potentialImpactText = "";
        if (detailedInformation != null && detailedInformation.parent() != null && detailedInformation.parent().parent() != null)
            detailedInformationText = detailedInformation.parent().parent().text();
        if (potentialImpact != null && potentialImpact.parent() != null && potentialImpact.parent().parent() != null)
            potentialImpactText = potentialImpact.parent().parent().text();

        ArrayList<String> detailedCVEs = getCVEIdsFromText(detailedInformationText.split(" "));
        ArrayList<String> impactCVEs = getCVEIdsFromText(potentialImpactText.split(" "));

        // remove duplicates
        ArrayList<String> combined = new ArrayList<>(cveTexts);
        combined.addAll(detailedCVEs);
        combined.addAll(impactCVEs);
        HashSet<String> cveIds = new HashSet<>(combined);

        // if no cves found we can return
        if (cveIds.isEmpty()) return vulnList;

        // otherwise continue with getting description from 'detailed information' and
        // 'potential impact' sections
        for (String cve : cveIds)
            vulnList.add(new CompositeVulnerability(
               0, sSourceURL, cve, null, publishedDate, lastUpdated, detailedInformationText + potentialImpactText, sourceDomainName
            ));

        return vulnList;
    }
}
