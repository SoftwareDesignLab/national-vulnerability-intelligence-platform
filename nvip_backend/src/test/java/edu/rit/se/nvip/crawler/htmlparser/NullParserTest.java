package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class NullParserTest extends AbstractParserTest {

    @Test
    public void testNull() {
        List<CompositeVulnerability> list = new NullParser().parseWebPage("null", "foobar");
        assertEquals(0, list.size());
    }
}