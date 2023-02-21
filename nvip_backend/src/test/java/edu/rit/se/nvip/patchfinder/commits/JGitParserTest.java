package edu.rit.se.nvip.patchfinder.commits;

import edu.rit.se.nvip.patchfinder.JGitCVEPatchDownloader;
import org.eclipse.jgit.util.FileUtils;
import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JGitParserTest {
    @Mock
    private CloneCommand cc;

    @org.junit.Before
    public void setUp() {
        ;
    }


    @Test
    public void JGitParserConstructorTest() {
        try {
            JGitParser jgp = new JGitParser("url/proj.ext", "nul");
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    public void cloneRepositoryTest() {
        try (MockedStatic<Git> git = Mockito.mockStatic(Git.class)) {
            // don't actually want to do any cloning during testing
            git.when(Git::cloneRepository).thenReturn(cc);
            JGitParser jgp = new JGitParser("url/proj.ext", "nul");
            jgp.cloneRepository();
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    public void deleteRepositoryTest() {
        JGitParser jgp = new JGitParser("url/proj.ext", "nul");
        // don't want to actually delete anything
        try (MockedStatic<FileUtils> filemock = Mockito.mockStatic(FileUtils.class)) {
            // just make sure a delete gets called
            jgp.deleteRepository();
            filemock.verify(() -> FileUtils.delete(any(), anyInt()));
        }
    }

    @Test
    public void testParseCommits() {

        String testCveId = "CVE-2006-2032";
        String testSourceURl = "https://github.com/plotly/dash-core-components.git";
        try (MockedStatic<Git> git = Mockito.mockStatic(Git.class)) {
            git.when(Git::cloneRepository).thenReturn(cc);
            JGitParser jGit = new JGitParser(testSourceURl, "src/test/resources/test-jgitparser/");
            jGit.cloneRepository();
            Map<Date, ArrayList<String>> commits = jGit.parseCommits(testCveId);
            assertEquals(2, commits.size());
            Date date = new Date(1617372481000L);
            assertTrue(commits.containsKey(date));
            assertEquals(2, commits.get(date).size());
            assertEquals("commit d6d24afd1a5f64d35f72a50edd2aed64089cf92e 1617372481 -----sp", commits.get(date).get(0));
            assertEquals("Merge pull request #942 from plotly/renovate/npm-y18n-vulnerability\n" +
                    "\n" +
                    "Update dependency y18n to 3.2.2 [SECURITY]", commits.get(date).get(1));
        } catch (Exception e) {
            fail();
        }

    }
}
