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

import org.python.core.PyInstance;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

/**
 * 
 * @author axoeec
 *
 */
public class PythonProcess {

	private String sRootDir = null;
	private String sPythonFile = null;
	private String sParams = null;
	PythonInterpreter interpreter = null;

	public PythonProcess(String sRootDir, String sPythonFile, String sParams) {
		super();
		this.sRootDir = sRootDir;
		this.sPythonFile = sPythonFile;
		this.sParams = sParams;

		interpreter = new PythonInterpreter();
	}

	PyInstance createClass(final String className, final String opts) {
		return (PyInstance) interpreter.eval(className + "(" + opts + ")");
	}

	public String exec() {

		// set your python program/class dir here
		interpreter.execfile(sRootDir + sPythonFile);

		// PyInstance pyInstance = createClass("WebCrawler", sRootDir+sParams);
		PyInstance pyInstance = createClass("WebCrawler", sParams);

		PyObject returnedObj = pyInstance.invoke("crawl");
		System.out.println("Got:" + returnedObj.toString());
		return returnedObj.toString();
	}
}
