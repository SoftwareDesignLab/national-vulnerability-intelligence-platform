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
import org.junit.jupiter.api.Test;


import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CurlParserTest extends AbstractParserTest {

    @Test
    public void testCurl0() {
        //https://curl.se/docs/CVE-2023-23916.html
        String html = safeReadHtml("src/test/resources/test-curl.html");
        List<CompositeVulnerability> list = new CurlParser("curl").parseWebPage("curl", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-23916", vuln.getCveId());
        assertEquals("2023/02/15 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("\"chained\" HTTP compression algorithms"));
        assertTrue(vuln.getDescription().contains("Automatic decompression of content needs to be enabled"));
    }

    @Test
    public void testCurl1() {
        //https://curl.se/docs/CVE-2022-43552.html
        String html = safeReadHtml("src/test/resources/test-curl-1.html");
        List<CompositeVulnerability> list = new CurlParser("curl").parseWebPage("curl", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-43552", vuln.getCveId());
        assertEquals("2022/12/21 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("curl can be asked to tunnel"));
        assertTrue(vuln.getDescription().contains("introduced for TELNET"));
    }
}