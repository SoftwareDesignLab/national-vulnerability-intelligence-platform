package edu.rit.se.utils;

import com.opencsv.CSVWriter;
import edu.rit.se.commits.GithubCommit;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import org.eclipse.egit.github.core.Commit;
import org.eclipse.egit.github.core.CommitFile;

/**
 * It extracts all commits from a GitHub repository that fixed vulnerabilities
 * (CVEs).
 *
 * @author Joanna C. S. Santos <jds5109@rit.edu>
 */
public class DataManager {

    /**
     * Save the commits into a file
     *
     * @param csvFile
     * @param commits
     * @throws IOException
     */
    public void saveCommits(File csvFile, List<GithubCommit> commits) throws IOException {
        try (CSVWriter writer = new CSVWriter(new FileWriter(csvFile))) {
            writer.writeNext(new String[]{"CVE ID", "commit_sha", "commit_message", "tree_sha"});//,"revision_download_url"});
            commits.forEach((obj) -> {
                Commit c = obj.getCommit();
                writer.writeNext(new String[]{
                    String.join(",", obj.getFoundCves()),
                    obj.getSha(), //"commit_sha",
                    c.getMessage(),//"commit_message",
                    c.getTree().getSha()//"tree_sha",
                });
                //c.getTree().getUrl()"revision_download_url"});
            });
        } //,"revision_download_url"});
    }

    /**
     * Saves data about affected files into a CSV file. CSV headers: "CVE ID",
     * "commit_sha", "file_path", "added", "deleted"
     *
     * @param csvFile path to the output CSV file
     * @param commits list of commits that fixed CVEs in a repository
     * @throws IOException
     */
    public void savePatchMetadata(File csvFile, List<GithubCommit> commits) throws IOException {
        try (CSVWriter writer = new CSVWriter(new FileWriter(csvFile))) {
            writer.writeNext(new String[]{"CVE ID", "commit_sha", "file_path", "added", "deleted"});
            commits.forEach((GithubCommit githubCommit) -> {
                githubCommit.getFoundCves().forEach((String cve) -> {
                    githubCommit.getAffectedFiles().forEach((CommitFile affectedFile) -> {
                        writer.writeNext(new String[]{
                            cve, // cve_id
                            githubCommit.getCommit().getSha(), //"commit_sha",
                            affectedFile.getFilename(),//"file_path",
                            String.valueOf(affectedFile.getAdditions()),//"added",
                            String.valueOf(affectedFile.getDeletions())//"deleted",
                        });
                    });
                });
            });
        }
    }
}
