package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class TalosIntelligenceParserTest extends AbstractParserTest {

	@Test
	public void testTalosIntelligence() {
		String html = safeReadHtml("src/test/resources/test-talos.html");
		List<CompositeVulnerability> list = new TalosIntelligenceParser("talosintelligence").parseWebPage("talosintelligence", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2016-2334", vuln.getCveId());
	}

}
