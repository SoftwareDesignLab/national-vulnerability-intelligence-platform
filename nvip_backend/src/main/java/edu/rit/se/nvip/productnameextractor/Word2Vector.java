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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.models.embeddings.loader.WordVectorSerializer;
import org.deeplearning4j.models.word2vec.Word2Vec;

/**
 * Word2Vector class for words embedding into 1D-vector
 * 
 * @author Igor Khokhlov
 *
 */

public class Word2Vector {
	
	private Word2Vec model;

	// This value is later updated from the loaded model
	private int vectorLength=0;
	
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	
	/**
	 * Class constructor
	 * @param String Model file path
	 */		
	public Word2Vector(String modelPath) {
		super();
		
		try {
			//Try to load the model
			model = WordVectorSerializer.loadFullModel(modelPath);
			//get expected vector length
			vectorLength = model.getLayerSize();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			logger.error(e);
		}		
	}
	
	/**
	 * Returns expected length of the vector after word embedding
	 * 
	 * @return expected length of the vector after word embedding
	 */	
	public int getOutVectorLength() {		
		return vectorLength;
	}
	
	/**
	 * Convert word into the 1D-vector
	 * 
	 * @param String input word
	 * @return array of double values
	 */	
	public double[] word2vector(String word) {
		
		word=word.toLowerCase();
				
		double[] doubleArray = null;
		
		try {
			doubleArray = model.getWordVector(word);
		} catch (Exception e) {
			//logger.error(e);
		}
		
		return doubleArray;
	}

}
