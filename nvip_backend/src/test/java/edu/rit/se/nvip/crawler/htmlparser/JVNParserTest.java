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

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class JVNParserTest extends AbstractParserTest {

    @Test
    public void testJVN1() {
        String html = safeReadHtml("src/test/resources/test-jvn-1.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://jvn.jp/jp/JVN11257333/index.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-22367", vuln.getCveId());
        // smartphone app "Ichiran Official App" developed by Btrend Co., Ltd
        assertTrue(vuln.getDescription().contains("ビートレンド株式会社が開発し、株式会社一蘭が提供するスマートフ"));
        // Please update to the latest version based on the information
        assertFalse(vuln.getDescription().contains("開発者が提供する情報をも"));
        assertEquals("2023/02/06", vuln.getPublishDate());
        assertEquals("2023/03/06", vuln.getLastModifiedDate());
    }

    @Test
    public void testJVN2() {
        String html = safeReadHtml("src/test/resources/test-jvn-2.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://jvn.jp/vu/JVNVU99322074/index.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-25931", vuln.getCveId());
        // clinician app provided by Medtronic contains the following
        assertTrue(vuln.getDescription().contains("Medtronicが提供する臨床医アプリに"));
        // The developer has provided an update.
        assertFalse(vuln.getDescription().contains("開発者は、アップデートを提供しています"));
        assertEquals("2023/03/03", vuln.getPublishDate());
        assertEquals("2023/03/03", vuln.getLastModifiedDate());
    }

    @Test
    public void testJVN3() {
        String html = safeReadHtml("src/test/resources/test-jvn-3.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://jvn.jp/vu/JVNVU90224831/index.html",
                html
        );
        assertEquals(2, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-14521");
        assertNotNull(vuln);
        // Multiple Mitsubishi Electric FA engineering software products
        assertTrue(vuln.getDescription().contains("複数の三菱電機製 FA エンジニアリングソフトウェア製品には"));
        assertEquals("2020/07/30", vuln.getPublishDate());
        assertEquals("2023/03/02", vuln.getLastModifiedDate());
    }

}
