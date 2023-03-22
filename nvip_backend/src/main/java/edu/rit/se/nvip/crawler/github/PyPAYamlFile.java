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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.nd4j.shade.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.util.*;

public class PyPAYamlFile {

    // PYSEC ID found at top of file
    private String id;

    // Vuln description
    private String details;

    // Affected Array of Obj
    // TODO: proper access methods and types
    private ArrayList<Object> affected;

    // Array of { type: String, url: String } objects
    // TODO: proper access methods
    private ArrayList<LinkedHashMap<String, String>> references;

    // Array of vuln aliases (CVE IDs located in here)
    private ArrayList<String> aliases = new ArrayList<>();

    // Last modified date
    private String modified;

    // Publish date
    private String published;

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    public PyPAYamlFile(File f) {
        try {

            InputStream inputStream = Files.newInputStream(f.toPath());
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(inputStream);
            this.id = data.get("id").toString();
            this.details = data.get("details").toString();
            this.affected = (ArrayList<Object>) data.get("affected");
            this.references = (ArrayList<LinkedHashMap<String, String>>) data.get("references");
            this.aliases = data.get("aliases") == null ? new ArrayList<>() : (ArrayList<String>) data.get("aliases");
            this.modified = data.get("modified").toString();
            this.published = data.get("published").toString();

        } catch (IOException fe) {
            logger.error("YAML Parser I/O exception for file: " + f.getName());
        }
    }

    public String getDetails() { return this.details; }

    public String getModified() { return this.modified; }

    public String getPublished() { return this.published; }

    public String getId() { return this.id; }

    /**
     * access aliases and search for any alias that contains a CVE id
     */
    public ArrayList<String> getCves() {
        ArrayList<String> cves = new ArrayList<>();
        if (this.aliases != null) {
            for (String alias : this.aliases) {
                if (alias.contains("CVE-"))
                    cves.add(alias);
            }
        }
        return cves;
    }
}
