/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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
package edu.rit.se.nvip.cvss.utils;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 
 * @author axoeec
 *
 */
public class ModelParams {
	/**
	 * DL CNN Config
	 */
	static final int batchSize = 32; // batch size for training
	static final int truncateDocumentsToLength = 256; // Truncate documents with length (# words) greater than this
	static final int printScorePerItems = 10; // print score (loss) per X itms
	static final Random randomNumberGenerator = new Random(12345); // For shuffling repeatability
	static final String wordVectorFile = "GoogleNews-vectors-negative300-SLIM.bin.gz";
	// static final String wordVectorFile = "CveWord2vec.gz";

	static final DecimalFormat decimalFormat = new DecimalFormat("0.##");

	static final int vectorSize = 300; // Size of the word vectors. 300 in the Google News model
	static final int cnnLayerFeatureMaps = 100; // Number of feature maps / channels / depth for each CNN layer

	public static List<String> getExploitabilityLabels() {
		List<String> exploitabilityLabels = new ArrayList<String>();
		exploitabilityLabels.add("0");
		exploitabilityLabels.add("1");
		return exploitabilityLabels;
	}

	public static List<String> getSeverityLabels() {
		List<String> severityLabels = new ArrayList<String>();
		severityLabels.add("1");
		severityLabels.add("4");
		severityLabels.add("7");
		severityLabels.add("10");
		return severityLabels;

	}

	public static enum MapType {
		CVE, SEVERITY, EXPLOITABILITY, DESCRIPTION
	}

	public static int getBatchsize() {
		return batchSize;
	}

	public static int getTruncatedocumentstolength() {
		return truncateDocumentsToLength;
	}

	public static int getPrintscoreperitems() {
		return printScorePerItems;
	}

	public static Random getRandomnumbergenerator() {
		return randomNumberGenerator;
	}

	public static String getWordvectorfile() {
		return wordVectorFile;
	}

	public static DecimalFormat getDecimalformat() {
		return decimalFormat;
	}

	public static int getVectorsize() {
		return vectorSize;
	}

	public static int getCnnlayerfeaturemaps() {
		return cnnLayerFeatureMaps;
	}

}
