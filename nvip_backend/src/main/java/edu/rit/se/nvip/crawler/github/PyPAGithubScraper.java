/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.crawler.github;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.GitController;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.util.FileUtils;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

public class PyPAGithubScraper {

    private static MyProperties propertiesNvip;

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    private static final String pypaDir = "pypa-repo";

    public PyPAGithubScraper() {
        propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

    }

    public HashMap<String, CompositeVulnerability> scrapePyPAGithub() {
        // clone or update pypa/advisory-database repo
        updateGitRepo();
        // extract CVEs from YAML files in /vulns subdirectories
        HashMap<String, CompositeVulnerability> vulnMap = extractCVEsFromVulns();
        // delete git repo once finished
        deleteRepository();
        logger.info("PyPA scraper completed.");

        return vulnMap;
    }

    private HashMap<String, CompositeVulnerability> extractCVEsFromVulns() {
        logger.info("Extracting CVEs from /vulns dir...");
        File vulnDir = Paths.get(propertiesNvip.getDataDir(), pypaDir, "vulns").toFile();
        File[] directories = vulnDir.listFiles();
        HashMap<String, CompositeVulnerability> vulnMap = new HashMap<>();
        if (directories == null) {
            logger.error("Failed to parse PyPA directories... returning.");
            return vulnMap;
        }
        // loop through each dir in /vulns
        for (File subdir : directories) {
            // parse each file in current sub dir
            if (subdir.isDirectory()) {
                File[] files = subdir.listFiles();
                if (files == null) {
                    logger.warn("Failed to locate files in subdirectory: " + subdir.getName());
                    continue;
                }
                for (File file : files ) {
                    logger.info("Parsing file: " + file.getName());
                    PyPAYamlFile parsedFile = new PyPAYamlFile(file);
                    ArrayList<String> cvesInFile = parsedFile.getCves();
                    for (String c : cvesInFile) {
                        vulnMap.put(c, (new CompositeVulnerability(
                                0, "", c, null, parsedFile.getPublished(), parsedFile.getModified(), parsedFile.getDetails(), ""
                        )));
                    }
                }
            }
        }
        return vulnMap;
    }

    /**
     * Clone or pull PyPA GitHub repo to be used for extraction
     */
    private void updateGitRepo() {
        // clone / pull to this local path
        Path gitFolder = Paths.get(propertiesNvip.getDataDir(), pypaDir);
        // clone / pull from this remote repository
        String remotePath = "https://github.com/pypa/advisory-database/";
        GitController gitController = new GitController(gitFolder.toString(), remotePath);

        File f = new File(gitFolder.toString());
        boolean pullDir = false;

        if (!f.exists())
            f.mkdirs();

        try {
            pullDir = f.exists() && Objects.requireNonNull(f.list()).length > 1;
        } catch (Exception ignored) {
        }

        // if already locally stored instance of repo, fetch latest
        if (pullDir) {
            if (gitController.pullRepo())
                logger.info("Pulled git repo at: " + remotePath + " to: " + gitFolder);
            else
                logger.error("Failed to pull git repo at: " + remotePath + " to: " + gitFolder);
        } else {
            if (gitController.cloneRepo())
                logger.info("Cloned git repo at: " + remotePath + " to: " + gitFolder);
            else
                logger.error("Could not clone git repo at: " + remotePath + " to: " + gitFolder);

        }
    }

    /**
     * Deletes repository from local dir
     * Once parsing is complete
     */
    public void deleteRepository() {
        logger.info("Deleting PyPA repo local instance...");
        try {
            // clone / pull to this local path
            Path gitFolder = Paths.get(propertiesNvip.getDataDir(), pypaDir);
            File dir = new File(gitFolder.toString());
            FileUtils.delete(dir, 1);
            logger.info("PyPA Repo deleted successfully!");
        } catch (IOException e) {
            logger.info(e.getMessage());
        }
    }
}
