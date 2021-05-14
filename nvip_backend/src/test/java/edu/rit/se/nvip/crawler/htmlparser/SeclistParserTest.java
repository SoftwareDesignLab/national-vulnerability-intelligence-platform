package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SeclistParserTest {

	@Test
	public void testSeclistParser() throws IOException {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		CveCrawler crawler = new CveCrawler(propertiesNvip);

		String html = FileUtils.readFileToString(new File("src/test/resources/test-seclist-cvedetail.html"));
		List<CompositeVulnerability> list = crawler.parseWebPage("seclists", html);
		assertEquals(1, list.size());

		html = FileUtils.readFileToString(new File("src/test/resources/test-seclist-date.html"));
		list = crawler.parseWebPage("seclists", html);
		assertEquals(1, list.size());
	}

}
