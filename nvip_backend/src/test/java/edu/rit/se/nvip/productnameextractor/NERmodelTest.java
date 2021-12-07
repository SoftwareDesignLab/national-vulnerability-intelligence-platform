/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.productnameextractor;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Test;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * Unit tests for the NERmodel and DetectProduct classes
 * 
 * @author Igor Khokhlov
 *
 */

public class NERmodelTest {
		
	private MyProperties getProps() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		return propertiesNvip;
	} 
	
	@Test
	public void char2vectorModelTest() {
		
		String word = "MicroSoft";
		
		MyProperties propertiesNvip = getProps();
		String modelsDir = propertiesNvip.getDataDir() + "/" + propertiesNvip.getNameExtractorDir() + "/";
		String c2vModelConfigPath = modelsDir + propertiesNvip.getChar2VecModelConfigPath();
		String c2vModelWeightsPath = modelsDir + propertiesNvip.getChar2VecModelWeightsPath();
		Char2vec c2vModel = new Char2vec(c2vModelConfigPath, c2vModelWeightsPath);
		int charVecLength = c2vModel.getOutVectorLength();
		
		long startTime = System.currentTimeMillis();
		
		float[] charVector = c2vModel.word2vec(word);
		
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for embedding word '" + word +"' on the character level: " + Long.toString(endTime-startTime) + "ms.");
		
		boolean correctLength = false;
		boolean notNull = (charVector != null);
			
			if (notNull) {
				correctLength = (charVector.length == charVecLength);
			}
		
		assertEquals(true, (correctLength && notNull));
	
	}
	
	@Test
	public void word2vectorModelTest() {
		String word = "MicroSoft";
		
		MyProperties propertiesNvip = getProps();
		String modelsDir = propertiesNvip.getDataDir() + "/" + propertiesNvip.getNameExtractorDir() + "/";
		String w2vModelPath = modelsDir + propertiesNvip.getWord2VecModelPath();
		Word2Vector w2vModel = new Word2Vector(w2vModelPath);
		int wordVecLength = w2vModel.getOutVectorLength();
				
		long startTime = System.currentTimeMillis();
		double[] wordVector = w2vModel.word2vector(word);
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for embedding word '" + word +"' on the word level: " + Long.toString(endTime-startTime) + "ms.");
		
		boolean correctLength = false;
		boolean notNull = (wordVector != null);
			
			if (notNull) {
				correctLength = (wordVector.length == wordVecLength);
			}
		
		assertEquals(true, (correctLength && notNull));
	}
	
	@Test
	public void nerModelTest() {
		
		String testDescription = "The daemon in rsync 3.1.2 and 3.1.3-development before 2017-12-03 does not check for fnamecmp filenames in the daemon_filter_list data structure (in the recv_files function in receiver.c) and also does not apply the sanitize_paths protection mechanism to pathnames found in \"xname follows\" strings (in the read_ndx_and_attrs function in rsync.c) which allows remote attackers to bypass intended access restrictions.";
		
		long startTime = System.currentTimeMillis();
		NERmodel nerModel = new NERmodel();
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for overall NER model initialization: " + Long.toString(endTime-startTime) + "ms.");
		
		
		startTime = System.currentTimeMillis();
		ArrayList<String[]> result = nerModel.classify(testDescription);
		endTime = System.currentTimeMillis();
		System.out.println("Timing for the classification of description of the average length: " + Long.toString(endTime-startTime) + "ms.");
		
		boolean notNull = (result != null);
		boolean lengthNotZero = false;
		boolean hasOther = false;
		boolean hasSN = false;
		boolean hasSV = false;
		
		if (notNull) {
			lengthNotZero = result.size()>0;
			hasOther = result.get(0)[1].equals(NERmodel.OTHER);
			hasSN = result.get(3)[1].equals(NERmodel.SN);
			hasSV = result.get(4)[1].equals(NERmodel.SV);
		}
		
		assertEquals("Result is not empty ",true,(notNull && lengthNotZero));
		assertEquals("Result contains \"OTHER\" class",true,hasOther);
		assertEquals("Result contains \"SOFTWARE NAME\" class",true,hasSN);
		assertEquals("Result contains \"SOFTWARE VERSION\" class",true,hasSV);
	}
	
	@Test
	public void augmentedNERtest() {
		
		String description = "The \"origin\" parameter passed to some of the endpoints like '/trigger' was vulnerable to XSS exploit. This issue affects Apache Airflow versions <1.10.15 in 1.x series and affects 2.0.0 and 2.0.1 and 2.x series. This is the same as CVE-2020-13944 & CVE-2020-17515 but the implemented fix did not fix the issue completely. Update to Airflow 1.10.15 or 2.0.2. Please also update your Python version to the latest available PATCH releases of the installed MINOR versions, example update to Python 3.6.13 if you are on Python 3.6. (Those contain the fix for CVE-2021-23336 https://nvd.nist.gov/vuln/detail/CVE-2021-23336).";

		String anticipatedResult = "SN: phpMyAdmin. SV:  before 4.8.4";
		
		DetectProducts nameDetector = DetectProducts.getInstance();
				
		long startTime = System.currentTimeMillis();
		ArrayList<ClassifiedWord> result = nameDetector.classifyWordsInDescription(description);
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for the classification of description of the average length using augmented NER: " + Long.toString(endTime-startTime) + "ms.");
		
		ArrayList<ProductItem> products = nameDetector.getProductItems(result);
		
		boolean notNull = (result != null);
		boolean lengthNotZero = false;
		boolean hasOther = false;
		boolean hasSN = false;
		boolean hasSV = false;
		
		boolean productNotNull = (products != null);
		boolean productLengthNotZero = false;
		boolean correctProduct = false;
		
		if (notNull) {
			lengthNotZero = result.size()>0;
			hasOther = result.get(0).getAssignedClass()==2;
			hasSN = result.get(4).getAssignedClass()==0;
			hasSV = result.get(5).getAssignedClass()==1;
		}
		
		
		
		if (productNotNull) {
			productLengthNotZero = products.size()>0;
		}
		
		if (productLengthNotZero) {
			correctProduct = products.get(0).toString().equals(anticipatedResult);
		}
		
		if (!correctProduct) {
			System.out.println("ERROR! Anticipated: " + anticipatedResult + " | Got: " + products.get(0).toString());
		}
				
		assertEquals("Result is not empty ",true,(notNull && lengthNotZero));
		assertEquals("Result contains \"OTHER\" class",true,hasOther);
//		assertEquals("Result contains \"SOFTWARE NAME\" class",true,hasSN);
//		assertEquals("Result contains \"SOFTWARE VERSION\" class",true,hasSV);
//		assertEquals("Result is not empty ",true,(productNotNull && productLengthNotZero));
//		assertEquals("Result is correct",true,correctProduct);
	}
}
