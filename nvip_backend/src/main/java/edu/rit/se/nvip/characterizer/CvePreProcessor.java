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
package edu.rit.se.nvip.characterizer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.preprocessor.PreProcCleanUp;
import edu.rit.se.nvip.characterizer.preprocessor.PreProcCodeTermExtractor;
import edu.rit.se.nvip.characterizer.preprocessor.PreProcStemmer;
import edu.rit.se.nvip.characterizer.preprocessor.PreProcStopWords;
import edu.rit.se.nvip.characterizer.preprocessor.PreProcessor;

/**
 * 
 * @author axoeec
 *
 */
public class CvePreProcessor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	public static String STOPWORDS_FILE = "stopwords_w_java_cpp_keywords.txt";
	PreProcessor[] preProcessors = new PreProcessor[4];
	private boolean removeCommonStopWords = true;

	public CvePreProcessor(boolean removeCommonStopWords) {
		super();

		this.removeCommonStopWords = removeCommonStopWords;

		PreProcessor preProc1 = new PreProcCleanUp(); // removes funny characters
		PreProcessor preProc2 = new PreProcCodeTermExtractor(); // tokenize the code identifiers
		PreProcessor preProc3 = new PreProcStopWords(STOPWORDS_FILE); // remove stop words
		PreProcessor preProc4 = new PreProcStemmer(); // stemming the words

		// Configures the order of the preprocessing: 1- CleanUp, 2-Terms Extraction,
		// 3-Stopwords Removal,
		// 4-Stemming
		if (removeCommonStopWords) {
			preProcessors = new PreProcessor[4];
			preProc1.setNextPreProcessor(preProc2.setNextPreProcessor(preProc3.setNextPreProcessor(preProc4)));

			preProcessors[0] = preProc1;
			preProcessors[1] = preProc2;
			preProcessors[2] = preProc3;
			preProcessors[3] = preProc4;
		} else {
			preProcessors = new PreProcessor[3];
			preProc1.setNextPreProcessor(preProc2.setNextPreProcessor(preProc4));

			preProcessors[0] = preProc1;
			preProcessors[1] = preProc2;
			preProcessors[2] = preProc4;

		}

	}

	/**
	 * Pre-process the first column of a given line of text. Assume that
	 * <preProcessors> stores the underlying "linked" processors
	 * 
	 * @param currentLine
	 * @param preProcessors
	 * @return
	 */
	public String preProcessLine(String currentLine) {
		List<String> forStop = null;
		List<String> forStem = null;
		List<String> last = null;

		StringBuffer processedLine = new StringBuffer();
		List<String> columns = Arrays.asList(currentLine.split(","));
		List<String> processed = preProcessors[0].process(columns.get(0));
		if (removeCommonStopWords) {
			for (String temp : processed) {
				forStop = preProcessors[1].process(temp);
				for (String temp2 : forStop) {
					forStem = preProcessors[2].process(temp2);
					for (String temp3 : forStem) {
						last = preProcessors[3].process(temp3);
						processedLine.append(last.get(0) + ' ');
					}
				}
			}
		} else {
			for (String temp : processed) {
				forStem = preProcessors[1].process(temp);
				for (String temp3 : forStem) {
					last = preProcessors[2].process(temp3);
					processedLine.append(last.get(0) + ' ');
				}

			}
		}

		return processedLine.toString();
	}

	/**
	 * Pre-process the lines of a CSV file that has two comma separated columns. The
	 * first column is the CVE text and the second column is the target class.
	 * 
	 * @param filePath
	 * @return
	 */
	public String preProcessFile(String filePath) {
		StringBuffer sBuffer = new StringBuffer();
		BufferedReader bReader = null;
		try {
			File file = new File(filePath);

			bReader = new BufferedReader(new FileReader(file));

			int lineCount = 0;

			String sLine;
			while ((sLine = bReader.readLine()) != null) {
				try {
					String[] columns = sLine.split(",");
					if (lineCount > 0) // take the first column as is
						sLine = preProcessLine(columns[0]) + "," + columns[1];
					else
						sLine = columns[0] + "," + columns[1]; // take the first columns, i.e. text,class

					sBuffer.append(sLine + "\n");
					lineCount++;
				} catch (Exception e) {
					logger.error("Skipping this line! An error occurred while pre-processing line [" + sLine + "] of file: " + filePath + " Err: " + e.toString());
				}
			}
			logger.info("Preprocessed " + lineCount + " items at " + filePath);
			return sBuffer.toString();
		} catch (FileNotFoundException e) {
			logger.error("Error during pre-processing " + filePath + "! Details: " + e.toString());
		} catch (IOException e) {
			logger.error("Error during pre-processing " + filePath + "! Details: " + e.toString());
		} catch (Exception e) {
			logger.error("Error during pre-processing " + filePath + "! Details: " + e.toString());
		} finally {
			if (bReader != null) {
				try {
					bReader.close();
				} catch (IOException e) {
					logger.error(e.toString());
				}
			}
		}

		return null;
	}
}
