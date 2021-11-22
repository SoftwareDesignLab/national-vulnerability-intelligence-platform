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
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author axoeec
 *
 */
public class PreProcCodeTermExtractor implements PreProcessor {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private static final String DELIM = " .,:;/?'\"[]{})(-_=+~!@#$%^&*<>\n\t\r1234567890";
	private static final String SPLIT_REGEX = "[A-Z][a-z]+|[a-z]+|[A-Z]+";

	// Next in the chain of command
	PreProcessor _next;

	public List<String> process(String content) {
		List<String> result = new ArrayList<String>();

		// 1- break down into tokens
		StringTokenizer st = new StringTokenizer(content, DELIM);

		// 2- For each token, it breaks down the terms
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			Pattern pattern = Pattern.compile(SPLIT_REGEX);
			Matcher m = pattern.matcher(token);
			while (m.find()) {
				String subStringFound = m.group();
				result.add(subStringFound.toLowerCase());
			}
		}

		return result;
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

}
