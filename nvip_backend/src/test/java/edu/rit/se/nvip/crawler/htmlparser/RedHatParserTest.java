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
		List<CompositeVulnerability> list = parser.parseWebPage("https://access.redhat.com/security/cve/cve-2023-25725", html);

		assertEquals(1, list.size());

		CompositeVulnerability sample = list.get(0);
		assertEquals("CVE-2023-25725", sample.getCveId());
		assertTrue(sample.getDescription().contains("A flaw was found in HAProxy's headers processing that causes HAProxy to drop important headers fields such as Connection, Content-length, Transfer-Encoding,"));
		assertEquals("2023-02-14T16:20", sample.getPublishDate());
		assertEquals("2023-04-06T06:22:55", sample.getLastModifiedDate());
	}
}
