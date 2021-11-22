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

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * 
 * @author Carlos Castro
 *
 *         This Pre-Processor cleans up the text, eliminating all 'non
 *         characters' (punctuation marks, numbers, etc) It is set up as a Chain
 *         of Command design pattern, where each preprocessor does its operation
 *         and calls on the next one This allows for dynamic set up of the
 *         pre-processing steps, as well as adding or removing steps later on
 *
 */
public final class PreProcCleanUp implements PreProcessor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	// Next in the chain of command

	PreProcessor _next;

	// Constructor - Package Private
	public PreProcCleanUp() {
	}

	public PreProcessor setNextPreProcessor(PreProcessor next) {
		// Integrity checks
		if (next == null) {
			throw new IllegalArgumentException("The next preProcessor can't be null");
		}

		// Sets the next chain link
		_next = next;

		return this;
	}

	public List<String> process(String text) {
		String initialText = text;
		List<String> results = new ArrayList<String>();
		String singleResult = "";

		// Reduces the text to only characters - using Regular Expressions
		singleResult = initialText.replaceAll("[^\\p{L}]", " ");
		// Eliminates any duplicate whitespace - using Regular Expressions
		singleResult = singleResult.replaceAll("\\s+", " ");
		results.add(singleResult);
		return results;

	}
}
