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
package edu.rit.se.nvip.characterizer.preprocessor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * @author Carlos Castro
 * 
 *         This Pre-Processor removes common stop words. It uses a file of
 *         common words as a reference. It is set up as a Chain of Command
 *         design pattern, where each preprocessor does its operation and calls
 *         on the next one This allows for dynamic set up of the pre-processing
 *         steps, as well as adding or removing steps later on
 *
 */
public class PreProcStopWords implements PreProcessor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	// Next in the chain of command
	PreProcessor _next;
	// Array list that holds the stopwords
	ArrayList<String> stopWords;

	// Constructor - Package Private
	public PreProcStopWords(String stopWordsFile) {

		try {
			// The args should specify the location of the stop words file
//			String stopWordsFile = args[0];

			// Array with the stop words
			stopWords = new ArrayList<String>();
			String stopWord;
			ClassLoader classLoader = getClass().getClassLoader();
			InputStream inputStream = classLoader.getResourceAsStream(stopWordsFile);

			BufferedReader in;
			in = new BufferedReader(new InputStreamReader(inputStream));

			// Reads the file
			while ((stopWord = in.readLine()) != null) {
				// Adds the stop word to the array
				stopWords.add(stopWord);
			}
			in.close();

		} catch (Exception e) {
			logger.error("The following error ocurred:\n" + e.getMessage());
			logger.error("Details:\n" + e.toString());
		}
	}

	public PreProcessor setNextPreProcessor(PreProcessor next) {
		// Integrity checks
		if (next == null)
			throw new IllegalArgumentException("The next preProcessor can't be null");

		// Sets the next chain link
		_next = next;

		return this;
	}

	public List<String> process(String text) {
		String initialText = text;
		List<String> results = new ArrayList<String>();

		// Splits the text into tokens and iterates over them
		String[] tokens = initialText.split(" ");
		for (String word : tokens) {
			// If the word is not in the stop list, it gets included
			if (!stopWords.contains(word)) {
				results.add(word);
			}
		}
		return results;
	}

}
