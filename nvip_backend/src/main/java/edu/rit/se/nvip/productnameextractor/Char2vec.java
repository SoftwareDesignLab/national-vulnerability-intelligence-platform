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

import java.io.IOException;
import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.nn.graph.ComputationGraph;
import org.deeplearning4j.nn.modelimport.keras.KerasModelImport;
import org.deeplearning4j.nn.modelimport.keras.exceptions.InvalidKerasConfigurationException;
import org.deeplearning4j.nn.modelimport.keras.exceptions.UnsupportedKerasConfigurationException;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

/**
 * Char2vec class for words embedding into 1D-vector on a character level
 * Uses a Keras model taken from https://hackernoon.com/chars2vec-character-based-language-model-for-handling-real-world-texts-with-spelling-errors-and-a3e4053a147d
 *
 * @author Igor Khokhlov
 *
 */

public class Char2vec {
		
	//Supported symbols
	private final char[] dict = {'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.',
            '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<',
            '=', '>', '?', '@', '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
            'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
            'x', 'y', 'z'};
	
	private ArrayList<Character> dictList = null; //just to take advantage of Collections

	private ComputationGraph model = null;
	
	// This value is later updated from the loaded model
	private int vectorLength = 50;

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Class constructor
	 * @param String Model config file path (json file)
	 * @param String Model weights' path (h5 file)
	 */	
	public Char2vec(String modelConfigPath, String modelWeightsPath) {
		super();

		try {
			//Try to load the Keras model. NOTE: in the config JSON file after model export, "class_name": "Functional" has to be changed to "class_name": "Model"
			model = KerasModelImport.importKerasModelAndWeights(modelConfigPath, modelWeightsPath);
			//get expected vector length
			vectorLength = (int) model.layerSize(0);
		} catch (IOException | UnsupportedKerasConfigurationException | InvalidKerasConfigurationException e) {
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
	 * Preprocess the word into the INDArray understanble by char2vec model
	 * 
	 * @param String input word
	 * @return features array that can be fed into the model
	 */	
	private INDArray preprocessWord(String wordToVec) {
				
		wordToVec=wordToVec.toLowerCase();
		
		//We don't know what symbols are not supported in the word, so we use ArrayList
		ArrayList<int[]> wordMatrix = new ArrayList<int[]>();
		
		if (dictList == null) {
			dictList = new ArrayList<>();
			for (int i=0; i<dict.length; i++) {
				dictList.add(dict[i]);
			}
		}
		 
		//Convert word into the vector (length = dict.length) of binary values, with only one "1" element, posistion of which corresponds to the this symbol position in the dict 
		for (int i=0; i<wordToVec.length(); i++) {
			char currentLetter = wordToVec.charAt(i);
			int position = dictList.indexOf(currentLetter);
			if (position>=0) {
				int[] letterVector = new int[dict.length]; 
				letterVector[position]=1;
				wordMatrix.add(letterVector);
			}
		}
		
		INDArray features = Nd4j.zeros(1,wordMatrix.size(),dict.length);
	
		//Converts our 2D-array into 3D-array acceptable by DL4J
		int[] indecies = new int[3];
		for (int i=0; i<wordMatrix.size(); i++) {
			indecies[1]=i;
			for (int j=0; j<dict.length; j++) {
				indecies[2]=j;
				features.putScalar(indecies, wordMatrix.get(i)[j]);
			}
		}
		
		return features;
	}	
	
	/**
	 * Convert features array into the 1D-vector
	 * 
	 * @param INDArray input features array
	 * @return array of float values
	 */
	private float[] processWords(INDArray features)
	{
		
		INDArray[] output = model.output(features); //Get output from he model

		INDArray outputRow = output[0].getRow(0);
		float[] resultVector = new float[outputRow.columns()];
		for (int i=0; i<resultVector.length; i++) {
			resultVector[i]=outputRow.getColumn(i).getFloat(0);
		}
		return resultVector;
	}
	
	/**
	 * Convert word into the 1D-vector
	 * 
	 * @param String input word
	 * @return array of float values
	 */	
	public float[] word2vec(String word) {
		
		//if word consists only from one symbol and this symbol is unsupported by the model, return null
		if (word.length()==1) {
			int position = dictList.indexOf(word.charAt(0));
			if (position<0) {
				return null;
			}
		}
		INDArray features = preprocessWord(word);
		return processWords(features);
	}

}
