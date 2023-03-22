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

public class TenableCveParserTest extends AbstractParserTest {
	public static final String TEST_DESCRIPTION = "A Missing Authorization vulnerability in of SUSE Rancher allows authenticated user to create an unauthorized shell pod and kubectl access in the local cluster This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.";
	@Test
	public void testTenableCveParser0() {
		String html = safeReadHtml("src/test/resources/test-tenable-newest.html");
		List<CompositeVulnerability> list = new TenableCveParser("tenable").parseWebPage("tenable.com/cve/newest", html);
		assertEquals(50, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-21953");
		assertNotNull(vuln);
		assertEquals(TEST_DESCRIPTION, vuln.getDescription());
	}

	@Test
	public void testTenableCveParser1() {
		String html = safeReadHtml("src/test/resources/test-tenable.html");
		List<CompositeVulnerability> list = new TenableCveParser("tenable").parseWebPage("tenable", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2022-21953", vuln.getCveId());
		assertEquals("2023/02/07 00:00:00", vuln.getPublishDate());
		assertEquals(TEST_DESCRIPTION, vuln.getDescription());
	}

}
