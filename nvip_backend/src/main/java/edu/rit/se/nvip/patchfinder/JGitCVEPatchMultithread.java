package edu.rit.se;

import edu.rit.se.commits.JGitParser;


public class JGitCVEPatchMultithread implements Runnable {
    private JGitParser parser;

    public JGitCVEPatchMultithread(JGitParser p){
        this.parser=p;
    }

    public void run() {
        try{
            parser.cloneRepository();
            parser.parseCommits();
        }
        catch (Exception e){
            System.err.println(e.toString());
        }
    }
}
