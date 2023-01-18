package edu.rit.se.nvip.patchfinder.commits;

import edu.rit.se.nvip.patchfinder.JGitCVEPatchDownloader;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class JGitParserTest {

    @Test
    public void testParseCommits() {

        String testCveId = "CVE-2006-2032";
        String testSourceURl = "https://github.com/plotly/dash-core-components.git";
        JGitParser jGit = new JGitParser(testSourceURl, "testpath");
        jGit.cloneRepository();
        Map<Date, ArrayList<String>> commits = jGit.parseCommits(testCveId);
        assertTrue(commits.size() > 0);

    }
}
