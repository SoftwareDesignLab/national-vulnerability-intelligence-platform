package edu.rit.se.nvip.patchfinder.commits;

import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.Test;
import org.mockito.Mock;

import static org.junit.Assert.*;

public class JGithubCommitTest {

    @Mock
    private RevCommit rc;

    @Test
    public void JGithubCommitTestAll() {
        String sha = "sha";
        JGithubCommit jgc = new JGithubCommit(sha, rc);
        assertEquals(rc, jgc.getCommit());
        assertEquals(sha, jgc.getSha());
    }
}