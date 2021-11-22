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
package edu.rit.se.nvip.pythoncrawler;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.nvd.NvdCveController;

/**
 * 
 * A bridge to execute external processes with Java Runtime
 * 
 * @author axoeec
 *
 */
public class ExternalRuntimeProcess {

	private String sRootDir = null;
	private String sCommand = null;
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Execute <sCommand> at <sRootDir>
	 * 
	 * @param sRootDir
	 * @param sCommand
	 */
	public ExternalRuntimeProcess(String sRootDir, String sCommand) {
		super();
		this.sRootDir = sRootDir;
		this.sCommand = sCommand;
	}

	/**
	 * Execute <sComamnd> with Java Runtime and return the output if any
	 * 
	 * @return
	 */
	public String exec() {
		String sOutput = "";
		Process process = null;
		int retCode = -1;
		try {

			logger.info("Running '" + sCommand + "' at path '" + sRootDir + "'");

			// get Java Runtime
			Runtime runtime = Runtime.getRuntime();
			process = runtime.exec(sCommand, null, new File(sRootDir));
			if (process == null)
				return null;

			// retCode = process.waitFor();

			// get error stream
			BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
			String sError = null;
			while ((sError = errorReader.readLine()) != null) {
				logger.error(sError);
			}
			errorReader.close();

			// get process input stream
			BufferedReader outputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String sLine = null;
			while ((sLine = outputReader.readLine()) != null) {
				sOutput += sLine;
			}
			outputReader.close();

		} catch (Exception e) {
			logger.error("Error running " + sCommand + "! " + e.toString());
		}

		// flush back
		OutputStream outputStream = process.getOutputStream();
		PrintStream printStream = new PrintStream(outputStream);
		printStream.println();
		printStream.flush();
		printStream.close();

		logger.info("Process returned: " + retCode + ", Output: " + sOutput);
		return sOutput;
	}

}
