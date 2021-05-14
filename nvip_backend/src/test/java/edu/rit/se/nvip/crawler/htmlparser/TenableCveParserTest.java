package edu.rit.se.nvip.crawler.htmlparser;

import static org.junit.Assert.assertEquals;

import java.net.URL;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;

public class TenableCveParserTest {
	@Test
	public void testTenableParser1() {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		try {
			String link = "https://www.tenable.com/cve/newest";
			String html = IOUtils.toString(new URL(link));
			List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage(link, html);
			assertEquals(true, list.size() > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
