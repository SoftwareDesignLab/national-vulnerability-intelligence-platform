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
package edu.rit.se.nvip.productnameextractor;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit tests for the FirstCommitWithCVE class
 * 
 * @author Igor Khokhlov
 *
 */

public class FirstCommitTest {

	@Test
	public void testGettingFirstCommit() {
		FirstCommitWithCVE firstCommitLookUp = FirstCommitWithCVE.getInstance();
		
		String legitCpeItem = "cpe:2.3:a:openmodelica:omcompiler:1.9.2:*:*:*:*:*:*:*";
		String legitCpeItemWOversion = "cpe:2.3:a:openmodelica:omcompiler:*:*:*:*:*:*:*:*";
		String notOpenSourceItem = "cpe:2.3:a:fabrikar:fabrik:3.0.4:*:*:*:*:joomla\\!:*:*";
		
		FirstCommitSearchResult result1 = firstCommitLookUp.getFirstCommit(legitCpeItem);
		FirstCommitSearchResult result2 = firstCommitLookUp.getFirstCommit(legitCpeItemWOversion);
		FirstCommitSearchResult result3 = firstCommitLookUp.getFirstCommit(notOpenSourceItem);
		
		String anticipatedResult1 = "v1.9.2";
		assertEquals("Result1 is correct", true, result1.getTagName().equals(anticipatedResult1));
		assertEquals("Result2 is correct", true, result2.getTagName()==null);
		assertEquals("Result3 is correct", true, result3==null);

	}

}
