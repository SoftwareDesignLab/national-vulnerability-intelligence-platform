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

/**
 * ClassifiedWord class for results of words classification in the CVE description into "Software Name", "Software Version", and "Others"
 * 0 - SN
 * 1 - SV
 * 2 - O
 * 
 * @author Igor Khokhlov
 *
 */

public class ClassifiedWord {
	
	private String word=null;
	private int assignedClass = -1;
	private float assignedClassConfidence = 0;
	private int numberOfClasses=0;
	private float[] confidences = null;
	
	/**
	 * Class constructor
	 */
	public ClassifiedWord(String word, float[] confidences) {
		super();
		this.word = word;
	
		this.confidences = confidences;
		numberOfClasses = confidences.length;
		assignClass();
		
	}
	
	/**
	 * Assigns class with the highest confidence
	 */	
	private void assignClass() {
		
		for (int i=0; i<confidences.length; i++) {
			if(confidences[i]>assignedClassConfidence) {
				assignedClassConfidence=confidences[i];
				assignedClass=i;
			}
		}	
	
	}

	/**
	 * Returns word that has been classified
	 * @return Word (strings)
	 */	
	public String getWord() {
		return word;
	}

	/**
	 * Returns assigned class of the classified word
	 * @return Class number (int)
	 */
	public int getAssignedClass() {
		return assignedClass;
	}

	/**
	 * Returns confidence of the assigned class of the classified word
	 * @return Confidence level (float)
	 */
	public float getAssignedClassConfidence() {
		return assignedClassConfidence;
	}

	/**
	 * Returns number of classes
	 * @return number of classes (int)
	 */
	public int getNumberOfClasses() {
		return numberOfClasses;
	}

	/**
	 * Returns all confidences of the class of the classified word
	 * @return vector of confidences (float[])
	 */
	public float[] getConfidences() {
		return confidences;
	}
	
	
	/**
	 * Sets class of the classified word
	 * @param Class number (int)
	 */
	public void setAssignedClass(int assignedClass) {
		this.assignedClass = assignedClass;
	}
	
	/**
	 * Sets class and its confidence of the assigned class of the classified word
	 * @param Class number (int)
	 * @param Confidence level (float)
	 */
	public void setAssignedClass(int assignedClass, float confidence) {
		this.assignedClass = assignedClass;
		this.assignedClassConfidence = confidence;
	}

	@Override
	public String toString() {
		
		if (word==null) {
			return "";
		}
		
		String classString = "";
		if (assignedClass==0) {
			classString = "SN";
		}
		else if (assignedClass==1) {
			classString = "SV";
		}
		else {
			classString = "O";
		}
		
		return word + "; " + classString;
	}
	
	
}
