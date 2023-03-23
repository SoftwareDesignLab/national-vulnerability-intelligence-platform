package edu.rit.se.nvip.mitre;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.mitre.capec.Capec;
import edu.rit.se.nvip.mitre.capec.CapecParser;
import edu.rit.se.nvip.mitre.capec.CapecRelationship;
import edu.rit.se.nvip.mitre.capec.CapecType;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class CapecTest {

    /**
     * helper to get attack pattern by id
     * @param id - id specified
     * @return - Capec encapsulation
     */
    protected static Capec getCapec(List<Capec> capecList, String id) {
        for (Capec c : capecList)
            if (c.getId().equals(id))
                return c;
        return null;
    }

    @Test
    public void testRelationship() {
        CapecRelationship capRel = new CapecRelationship("ChildOf", "Meta Attack Pattern", "122", "Privilege Abuse");
        assertEquals(CapecType.META, capRel.getType());
    }

    @Test
    public void testParser() {
        CapecParser parser = new CapecParser();
        QuickCveCrawler crawler = new QuickCveCrawler();
        List<Capec> capecs = parser.parseWebPage(crawler);
        assertEquals(559, capecs.size());
        Capec capec1 = getCapec(capecs, "1");
        assertNotNull(capec1);
        assertEquals(CapecType.STANDARD, capec1.getAbstraction());
        assertTrue(capec1.getDescription().contains("access to functionality is mitigated by an authorization framework"));
        assertEquals("High", capec1.getLikelihood());
        assertEquals("High", capec1.getSeverity());
        assertEquals(6,capec1.getRelationships().size());
        assertEquals(3, capec1.getPrereqs().size());
        assertEquals(1, capec1.getSkills().size());
        assertTrue(capec1.getResources().contains("None:"));
        assertEquals(3, capec1.getConsequences().size());
        assertTrue(capec1.getMitigations().contains("role that is impossible for the authenticator to grant user"));
        assertTrue(capec1.getExamples().contains("Java EE's Servlet"));
        assertEquals(16, capec1.getWeaknesses().size());
        assertEquals(1, capec1.getTax().size());

    }

}
