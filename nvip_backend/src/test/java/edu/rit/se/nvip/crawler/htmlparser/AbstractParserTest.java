package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.fail;

public abstract class AbstractParserTest {

    protected static String safeReadHtml(String path) {
        String html = null;
        try {
            html = FileUtils.readFileToString(new File(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
        return html;
    }

    protected static CompositeVulnerability getVulnerability(List<CompositeVulnerability> list, String cveID) {
        for (CompositeVulnerability vuln : list)
            if (vuln.getCveId().equalsIgnoreCase(cveID))
                return vuln;
        return null;
    }
}
