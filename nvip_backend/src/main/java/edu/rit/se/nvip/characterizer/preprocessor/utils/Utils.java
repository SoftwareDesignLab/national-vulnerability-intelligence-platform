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
package edu.rit.se.nvip.characterizer.preprocessor.utils;

import java.io.File;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author axoeec
 *
 */
public class Utils {
	private static Logger logger = LogManager.getLogger(Utils.class);

	static public void createDir(String dir) {
		boolean success = new File(dir).mkdir();
		if (success) {
			logger.info("Directory: " + dir + " created");
		} else {
			logger.error("Couln't create " + dir);
		}
	}

	static public String getRelativeFilePath(String filepath, String curDir) {
		filepath = filepath.trim().replace("\\", "/");
		String tokens[] = filepath.split(curDir);
		filepath = tokens[tokens.length - 1];
		return filepath;
	}

	// should make the filepath have the same format whenever they are used, so
	// getRelativeFilePath
	// should be removed and only getRelativeFilePath2 should be used in the future
	static public String getRelativeFilePath2(String filepath, String curDir) {
		filepath = filepath.trim().replace("\\", "/");
		String tokens[] = filepath.split(curDir);
		filepath = "/" + tokens[tokens.length - 1];
		if (filepath.startsWith("//"))
			filepath = filepath.substring(1);
		return filepath;
	}
}
