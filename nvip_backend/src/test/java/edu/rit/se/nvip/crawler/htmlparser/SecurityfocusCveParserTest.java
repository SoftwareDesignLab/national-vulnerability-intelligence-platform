package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class SecurityfocusCveParserTest {

	@Test
	public void testSecurityfocusParser() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		CveCrawler crawler = new CveCrawler(propertiesNvip);		
		String html = FileUtils.readFileToString(new File("src/test/resources/test-securityfocus.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.securityfocus.com/bid/76394", html);
		boolean foundCve = list.size() == 1;

		assertTrue(foundCve);
	}

}
