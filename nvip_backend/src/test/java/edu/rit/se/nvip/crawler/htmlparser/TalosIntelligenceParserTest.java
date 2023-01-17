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

public class TalosIntelligenceParserTest {

	@Test
	public void testTalosIntelligence() throws IOException {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		
		CveCrawler crawler = new CveCrawler(propertiesNvip);
		String html = FileUtils.readFileToString(new File("src/test/resources/test-talos.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("talosintelligence", html);
		assertTrue(list.size() > 0);
	}

}
