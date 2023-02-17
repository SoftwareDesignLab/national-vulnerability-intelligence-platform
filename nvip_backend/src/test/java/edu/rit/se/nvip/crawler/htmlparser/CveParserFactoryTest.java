package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static edu.rit.se.nvip.crawler.htmlparser.TenableCveParserTest.TEST_DESCRIPTION;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;


public class CveParserFactoryTest extends AbstractParserTest{

    CveParserFactory parserFactory = new CveParserFactory();
    AbstractCveParser parser;

    @Test
    public void testFactoryTenable() {
        String html = safeReadHtml("src/test/resources/test-tenable.html");
        String sSourceURL = "https://www.tenable.com/cve/CVE-2022-21953";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TenableCveParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-21953", vuln.getCveId());
        assertEquals("2023/02/07 00:00:00", vuln.getPublishDate());
        assertEquals(TEST_DESCRIPTION, vuln.getDescription());
    }

    @Test
    public void testFactoryTenableSec() {
        String html = safeReadHtml("src/test/resources/test-tenable-security.html");
        String sSourceURL = "https://www.tenable.com/security/research/tra-2023-5";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TenableSecurityParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0587", vuln.getCveId());
        assertEquals("2023/01/30 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A file upload vulnerability in exists in Trend Micro Apex One"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }

    @Test
    public void testFactoryExploitDB() {
        String html = safeReadHtml("src/test/resources/test-exploit-db.html");
        String sSourceURL = "https://www.exploit-db.com/exploits/51031";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), ExploitDBParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-37661", vuln.getCveId());
        assertEquals("2022-11-11", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Remote Code Execution"));
    }

    @Test
    public void testFactoryKbCert() {
        String html = safeReadHtml("src/test/resources/test-kb-cert-single.html");
        String sSourceURL = "https://www.kb.cert.org/vuls/id/434994";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), KbCertCveParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2021-33164", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("access and validation of the SMRAM"));
        assertEquals("2022/11/08 00:00:00", vuln.getPublishDate());
    }

    @Test
    public void testFactoryPacketStorm() {
        String html = safeReadHtml("src/test/resources/test-packetstorm-files-2.html");
        String sSourceURL = "https://packetstormsecurity.com/files/170988/Cisco-RV-Series-Authentication-Bypass-Command-Injection.html";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), PacketStormParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(2, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-20705");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Cisco RV160, RV260, RV340, and RV345 Small Business Routers, allowing attackers to execute arbitrary commands"));
        assertEquals("2023/02/14 00:00:00", vuln.getPublishDate());
    }

    @Test
    public void testFactoryTalos() {
        String html = safeReadHtml("src/test/resources/test-talos.html");
        String sSourceURL = "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1124";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TalosIntelligenceParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-40224", vuln.getCveId());
        assertEquals("2022/10/14 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A denial of service vulnerability exists"));
    }

    @Test
    public void testFactoryGentooBugs() {
        String html = safeReadHtml("src/test/resources/test-bugs-gentoo-single-cve.html");
        String sSourceURL = "https://bugs.gentoo.org/600624";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BugsGentooParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2013-4392", vuln.getCveId());
    }

    @Test
    public void testFactoryGentooSecurity() {
        String html = safeReadHtml("src/test/resources/test-security-gentoo-single.html");
        String sSourceURL = "https://security.gentoo.org/glsa/200502-21";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), SecurityGentooParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2005-0453", vuln.getCveId());
    }

    @Test
    public void testFactoryVMWare() {
        String html = safeReadHtml("src/test/resources/test-vmware-advisories-single-cve.html");
        String sSourceURL = "https://www.vmware.com/security/advisories/VMSA-2023-0003.html";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), VMWareAdvisoriesParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-20854", vuln.getCveId());
    }

    @Test
    public void testFactoryBugzilla() {
        String html = safeReadHtml("src/test/resources/test-bugzilla-cvedetail-2.html");
        String sSourceURL = "https://bugzilla.redhat.com/show_bug.cgi?id=1576652";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BugzillaParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2018-3736", vuln.getCveId());
    }

    @Test
    public void testFactorySecLists() {
        String html = safeReadHtml("src/test/resources/test-seclist.html");
        String sSourceURL = "https://seclists.org/bugtraq/2016/Feb/147";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), SeclistsParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2016-0763", vuln.getCveId());
    }

    @Test
    public void testFactoryRedhat() {
        String html = safeReadHtml("src/test/resources/test-redhat-security-2.html");
        String sSourceURL = "https://access.redhat.com/security/cve/cve-2023-25725";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), RedHatParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-25725", vuln.getCveId());
    }

    @Test
    public void testFactoryBosch() {
        String html = safeReadHtml("src/test/resources/test-bosch-security-2.html");
        String sSourceURL = "https://psirt.bosch.com/security-advisories/bosch-sa-464066-bt.html";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BoschSecurityParser.class);
        List<CompositeVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-32540", vuln.getCveId());
    }

    @Test
    public void testFactoryGoogleCloud() {
        String html = safeReadHtml("src/test/resources/test-google-cloud-bulletin.html");
        String sSourceURL = "https://cloud.google.com/support/bulletins";
        parser = parserFactory.createParser(sSourceURL);
        assertNotNull(parser);
        assertEquals(parser.getClass(), GoogleCloudParser.class);
        assertNotEquals(parser.parseWebPage(sSourceURL, html).size(), 0);
    }

    @Test
    public void testFactoryNull() {
        parser = parserFactory.createParser(null);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("gentoo......news");
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("gentoo......blogs");
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("mitre.org");
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("nist.gov");
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);

    }
}
