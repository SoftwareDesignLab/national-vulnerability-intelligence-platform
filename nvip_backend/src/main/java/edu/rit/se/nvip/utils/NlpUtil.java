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
package edu.rit.se.nvip.utils;

import java.io.IOException;
import java.io.InputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;

/**
 * 
 * @author 15854
 *
 */
public class NlpUtil {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	SentenceModel sentenceModel = null;
	SentenceDetector sentenceDetector = null;
	String sentenceModelPath = "nlp/en-sent.bin";

	public NlpUtil() {
		try {
			InputStream modelIn = this.getClass().getClassLoader().getResourceAsStream(sentenceModelPath);
			sentenceModel = new SentenceModel(modelIn);
			sentenceDetector = new SentenceDetectorME(sentenceModel);
			modelIn.close();
		} catch (IOException e) {
			logger.error("Error initializing Apache Open NLP sentence detector from {}", sentenceModelPath);
		}
	}

	/**
	 * Get sentences from text
	 * 
	 * @param text
	 * @return
	 */
	public String[] sentenceDetect(String text) {
		// detect sentences in the text
		String[] sentences = null;
		try {
			sentences = sentenceDetector.sentDetect(text);
		} catch (Exception e) {
			logger.error("Error getting sentences from text {}", text);
		}

		return sentences;
	}
}
