package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Test RedHat Parser
 * @author aep7128
 */
public class RedHatParserTest extends AbstractParserTest {

	@Test
	public void testRedHat() {
		RedHatParser parser = new RedHatParser("redhat");
		String html = safeReadHtml("src/test/resources/test-redhat-cve.html");
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);

		assertEquals(1, list.size());

		CompositeVulnerability sample = list.get(0);
		assertEquals("CVE-2023-25725", sample.getCveId());
		assertTrue(sample.getDescription().contains("A flaw was found in HAProxy's headers processing that causes HAProxy to drop important headers fields such as Connection, Content-length, Transfer-Encoding,"));
		assertEquals("February 14, 2023", sample.getPublishDate());
		assertEquals("February 14, 2023", sample.getLastModifiedDate());
	}
}
