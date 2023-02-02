package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NullParserTest {

    @Test
    void testNull() {
        List<CompositeVulnerability> list = new NullParser().parseWebPage("null", "foobar");
        assertEquals(0, list.size());
    }
}