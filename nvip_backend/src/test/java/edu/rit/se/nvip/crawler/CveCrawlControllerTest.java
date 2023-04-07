package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertTrue;

public class CveCrawlControllerTest {

    @Test
    public void CveCrawlControllerTest() throws Exception {
        List<String> urls = new ArrayList<>();
        urls.add("https://www.jenkins.io/security/advisory/2023-03-21/");

        CveCrawlController controller = new CveCrawlController();
        HashMap<String, ArrayList<CompositeVulnerability>> map = controller.crawlwProps(urls, new ArrayList<>());

        System.out.println(map);

        assertTrue(map.size() > 0);
}

}
