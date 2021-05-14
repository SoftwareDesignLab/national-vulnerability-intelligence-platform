/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 
 * NVIP Properties
 * 
 * @author axoeec
 *
 */

public class MyProperties extends Properties {
	private static final long serialVersionUID = 1L;

	public int getNumberOfCrawlerThreads() {
		return Integer.parseInt(getProperty("numberOfCrawlerThreads"));
	}

	public int getCrawlSearchDepth() {
		return Integer.parseInt(getProperty("crawlSearchDepth"));
	}

	public String getOutputDir() {
		return getProperty("outputDir");
	}

	public String getDataDir() {
		return getProperty("dataDir");
	}

	public String getDatabaseType() {
		return getProperty("database");
	}

	public String getNvdOutputCsvFullPath() {
		return getDataDir() + "/" + getProperty("nvdOutputCsvPath");
	}

	public String getMitreLocalRepoFullPath() {
		return getDataDir() + "/" + getProperty("mitreLocalRepoPath");
	}

	public String getMitreRemoteRepoPath() {
		return getProperty("mitreRemoteRepoPath");
	}

	public String getMitreOutputCsvFullPath() {
		return getDataDir() + "/" + getProperty("mitreOutputCsvpath");
	}

	public String getCnnvdLocalRepoFullPath() {
		return getDataDir() + "/" + getProperty("cnnvdLocalRepoPath");
	}

	public String getCnnvdOutputFileFullPath() {
		return getDataDir() + "/" + getProperty("cnnvdOutputFilePath");
	}

	public String getPathAllCrawledCVEs() {
		return getProperty("pathAllCrawledCVEs");
	}

	public String getPathCVEsNotInNvd() {
		return getProperty("pathCVEsNotInNvd");
	}

	public String getPathCVEsNotInMitre() {
		return getProperty("pathCVEsNotInMitre");
	}

	public String getPathCVEsNotInNvdAndMitre() {
		return getProperty("pathCVEsNotInNvdAndMitre");
	}

	public String getPathCVEsNewToday() {
		return getProperty("pathCVEsNewToday");
	}

	public String getPathCVEsDisappearedToday() {
		return getProperty("pathCVEsDisappearedToday");
	}

	public String getNvipUrlSources() {
		return getProperty("nvipUrlSources");
	}

	/**
	 * get VDO training data info
	 * 
	 * @return
	 * 
	 *         The root directory of the VDO data and comma separated names of the
	 *         CSV files
	 */
	public String[] getCveCharacterizationTrainingDataInfo() {
		String rootDir = getCveCharacterizationTrainingDataDirectory();
		String fileName = getProperty("cveCharacterizationTrainingData");
		String[] info = new String[] { rootDir, fileName };
		return info;
	}

	public String getCveCharacterizationTrainingDataDirectory() {
		String rootDir = getDataDir() + "/" + getProperty("cveCharacterizationTrainingDataDir") + "/";
		return rootDir;
	}

	public String getNvipUrlSourcesFullPath() {
		return getDataDir() + "/" + getProperty("nvipUrlSources");
	}

	public String getCveCharacterizationApproach() {
		return getProperty("cveCharacterizationApproach");
	}

	public String getCveCharacterizationMethod() {
		return getProperty("cveCharacterizationMethod");
	}

	public String getCveReconciliationMethod() {
		return getProperty("cveReconcileMethod");
	}

	public String getNameExtractorDir() {
		return getProperty("nameextractorDir");
	}

	public String getChar2VecModelConfigPath() {
		return getProperty("char2vecConfig");
	}

	public String getChar2VecModelWeightsPath() {
		return getProperty("char2vecWeights");
	}

	public String getWord2VecModelPath() {
		return getProperty("word2vec");
	}

	public String getNerModelPath() {
		return getProperty("nerModel");
	}

	public String getNerModelNormalizerPath() {
		return getProperty("nerModelNormalizer");
	}

	public String getCPEserialized() {
		return getProperty("cpeSerialized");
	}

	/**
	 * Hash map storing the list of known Cve sources (domains) that the system has
	 * a parser for
	 * 
	 * @return
	 */
	public Map<String, Integer> getKnownCveSources() {
		String sources = getProperty("knownSources");

		if (sources == null)
			return new HashMap<>(); // if no sources are specified!

		String[] arr = sources.split(",");
		Map<String, Integer> knownSourceMap = new HashMap<>();

		for (String url : arr)
			knownSourceMap.put(url, 0);

		return knownSourceMap;
	}

	/**
	 * politeness delay for default crawler
	 * 
	 * @return
	 */
	public int getDefaultCrawlerPoliteness() {
		String val = getProperty("defaultCrawlerPoliteness");
		if (val == null)
			val = "100"; // if not set in the property file
		return Integer.parseInt(val);
	}

	/**
	 * politeness delay for delayed (slower) crawler
	 * 
	 * @return
	 */
	public int getDelayedCrawlerPoliteness() {
		String val = getProperty("delayedCrawlerPoliteness");
		if (val == null)
			val = "150"; // if not set in the property file
		return Integer.parseInt(val);
	}

}
