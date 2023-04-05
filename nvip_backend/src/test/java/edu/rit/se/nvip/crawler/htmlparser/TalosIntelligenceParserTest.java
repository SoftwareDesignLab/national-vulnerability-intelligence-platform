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

import static org.junit.Assert.*;

public class TalosIntelligenceParserTest extends AbstractParserTest {

	@Test
	public void testTalosIntelligence() {
		String html = safeReadHtml("src/test/resources/test-talos.html");
		List<CompositeVulnerability> list = new TalosIntelligenceParser("talosintelligence").parseWebPage("talosintelligence", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2022-40224", vuln.getCveId());
		assertEquals("2022/10/14 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("A denial of service vulnerability exists"));
		assertTrue(vuln.getDescription().contains("An HTTP request to port 443"));
		assertFalse(vuln.getDescription().contains("Discovered by Patrick"));
	}


	@Test
	public void testTalosIntelligence2() {
		String html = safeReadHtml("src/test/resources/test-talos-2.html");
		List<CompositeVulnerability> list = new TalosIntelligenceParser("talosintelligence").parseWebPage("talosintelligence", html);
		assertEquals(3, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-41313");
		assertNotNull(vuln);
		assertEquals("2022/10/14 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("The SDS-3008 is an 8-port smart Ethernet switch"));
		assertTrue(vuln.getDescription().contains("A stored cross-site scripting vulnerability"));
		assertFalse(vuln.getDescription().contains("The following input in"));
	}

}
