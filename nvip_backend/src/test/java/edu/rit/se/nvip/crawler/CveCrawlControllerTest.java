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
        MyProperties properties = new MyProperties();
        properties = new PropertyLoader().loadConfigFile(properties);

        List<String> urls = new ArrayList<>();
        urls.add("https://access.redhat.com/security/cve/cve-2021-44228");

        CveCrawlController controller = new CveCrawlController();
        HashMap<String, CompositeVulnerability> map = controller.crawl(urls);

        System.out.println(map);

        assertTrue(map.size() > 0);
}

}
