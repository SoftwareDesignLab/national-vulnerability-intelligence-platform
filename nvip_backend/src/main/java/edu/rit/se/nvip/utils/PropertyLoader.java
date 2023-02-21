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

import java.io.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * Implementation of some commonly used utilities
 * 
 * @author axoeec
 *
 */
public class PropertyLoader {
	Logger logger = LogManager.getLogger(PropertyLoader.class);

	/**
	 * init NVIP properties
	 */
	public MyProperties loadConfigFile(MyProperties propertiesNVIP) {
		InputStream inputStream = null;

		try {
			// get config file from the root dir
			inputStream = new FileInputStream("nvip.properties");
		} catch (FileNotFoundException e) {
			try {
				String currDir = System.getProperty("user.dir");
				logger.warn("Could not locate the config file in the application root path \"{}\", getting it from resources! Warning: {}", currDir, e.getMessage());
				// not there? Get it from resources!
				ClassLoader classLoader = getClass().getClassLoader();
				inputStream = classLoader.getResourceAsStream("nvip.properties");
			} catch (Exception e1) {
				System.err.println("Could not locate the config file at src/main/resources/nvip.properties!");
				System.exit(1);
			}
		}

		try {
			// load values from input stream
			propertiesNVIP.load(inputStream);
			logger.info("Loaded {} parameters from .properties file!", propertiesNVIP.size());
		} catch (IOException e) {
			System.err.println("Error! Could not load parameters from the config file! " + e);
			System.exit(1);
		} finally {
			try {
				if (inputStream != null)
					inputStream.close();
			} catch (IOException ignored) {
			}
		}

		return propertiesNVIP;
	}

}
