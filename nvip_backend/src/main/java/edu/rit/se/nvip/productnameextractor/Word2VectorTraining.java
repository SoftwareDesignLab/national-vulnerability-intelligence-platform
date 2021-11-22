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
package edu.rit.se.nvip.productnameextractor;

import java.io.FileNotFoundException;
import java.util.Collection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.models.embeddings.loader.WordVectorSerializer;
import org.deeplearning4j.models.word2vec.Word2Vec;
import org.deeplearning4j.text.sentenceiterator.BasicLineIterator;
import org.deeplearning4j.text.sentenceiterator.SentenceIterator;
import org.deeplearning4j.text.tokenization.tokenizer.preprocessor.CommonPreprocessor;
import org.deeplearning4j.text.tokenization.tokenizerfactory.DefaultTokenizerFactory;
import org.deeplearning4j.text.tokenization.tokenizerfactory.TokenizerFactory;

/**
 * Word2VectorTraining class for training words embedding model
 * 
 * @author Igor Khokhlov
 *
 */

public class Word2VectorTraining {
	
	private static Logger logger = LogManager.getLogger(Word2VectorTraining.class);
	
	private static int outLenght = 250;
	private static String testWord = "day";

	/**
	 * Trains the word embedding model
	 * @param String corpus data file path
	 * @param String model data file path
	 * @param Optional - String length of the output vector (by default 250)
	 * @param Optional - word to test the model
	 * 
	 * Calling examples:
	 * d:\RIT\NVIP\raw_sentences.txt d:\RIT\NVIP\testWord2VecModel.bin 50 Vulnerability
	 * d:\RIT\NVIP\raw_sentences.txt d:\RIT\NVIP\testWord2VecModel.bin 50
	 * d:\RIT\NVIP\raw_sentences.txt d:\RIT\NVIP\testWord2VecModel.bin Vulnerability
	 * d:\RIT\NVIP\raw_sentences.txt d:\RIT\NVIP\testWord2VecModel.bin
	 */		
	public static void main(String[] args) {
		
		if (args.length<2) {
			logger.error("Not enough arguments");
			return;
		}
		
		if (args[0].length() < 1 || args[1].length() < 1) {
			logger.error("At least one of the file paths is invalid!");
			return;
		}
		
		boolean thirdArgIsLength = false;
		if (args.length>2) { 
			try {
				outLenght = Integer.parseInt(args[2]);
				thirdArgIsLength = true;
				logger.info("Output length was set to " + Integer.toString(outLenght));
			} catch (Exception e) {
				logger.info("Third argument is not Output Length.");
			}
		}
		
		if (!thirdArgIsLength && args.length>2) {
			testWord = args[2].toLowerCase();
			logger.info("Test word was set to '" + testWord + "'" );
			if (args.length>3) {
				try {
					outLenght = Integer.parseInt(args[3]);
					thirdArgIsLength = true;
					logger.info("Output length was set to " + Integer.toString(outLenght));
				} catch (Exception e) {
					logger.info("Fourth argument is not Output Length.");
				}
			}
		}
		else {
			if (args.length>3) {
				testWord = args[3].toLowerCase();
				logger.info("Test word was set to '" + testWord + "'" );
			} 
		}
		
		String filePathData = args[0];
		String filePathModel = args[1];
		
		logger.info("Model paramenters are:");
		logger.info("Data file path: " + filePathData);
		logger.info("Model file path: " + filePathModel);
		logger.info("Output vector length is " + Integer.toString(outLenght));
		logger.info("Test word is '" + testWord + "'" );

		
		logger.info("Load & Vectorize Sentences....");
		// Strip white space before and after for each line
		SentenceIterator iter = null;
		try {
			iter = new BasicLineIterator(filePathData);
		} catch (FileNotFoundException e) {
			logger.error(e);
			return;
		}
		// Split on white spaces in the line to get words
		TokenizerFactory t = new DefaultTokenizerFactory();

		/*
          CommonPreprocessor will apply the following regex to each token: [\d\.:,"'\(\)\[\]|/?!;]+
          So, effectively all numbers, punctuation symbols and some special symbols are stripped off.
          Additionally it forces lower case for all tokens.
		 */
		t.setTokenPreProcessor(new CommonPreprocessor());
      
		logger.info("Building model....");
	    Word2Vec vec = new Word2Vec.Builder()
	            .minWordFrequency(5)
	            .iterations(1)
	            .layerSize(outLenght)
	            .seed(42)
	            .windowSize(5)
	            .iterate(iter)
	            .tokenizerFactory(t)
	            .build();
	
	    logger.info("Fitting Word2Vec model....");
	    vec.fit();
	    
	    logger.info("Saving model....");
	    WordVectorSerializer.writeFullModel(vec, filePathModel);
	    
	    logger.info("TESTING MODEL PHASE.");
	    
	    logger.info("Loading model....");
	    Word2Vec testModel = null;
	    try {
			testModel = WordVectorSerializer.loadFullModel(filePathModel);
		} catch (FileNotFoundException e) {
			logger.error(e);
			return;
		}
	    
	    logger.info("Closest words to '"+testWord+"':");
	    
	    Collection<String> lst = null;
        try {
        	lst = testModel.wordsNearestSum(testWord, 10);
        	logger.info("10 Words closest to '"+testWord+"': {}", lst);
		} catch (Exception e) {
			logger.error("Model does not know word '"+testWord+"'");
		}
        
        double[] wordVector = testModel.getWordVector(testWord);
        if (wordVector != null) {
        	logger.info("Output vector length for the word "+testWord+"' is " + Integer.toString(wordVector.length));
        }
        else {
        	logger.error("Output vector for the word "+testWord+"' is NULL");
        }
	}

}
