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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
import java.util.Random;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * @author mmirak
 */
public class RandomCode {

	public RandomCode() {
		i = 0;
	}

	private static final String DELIM = " .,:;/?'\"[]{})(-_=+~!@#$%^&*<>\n\t\r1234567890";
	private static final String SPLIT_REGEX = "[A-Z][a-z]+|[a-z]+|[A-Z]+";
	private static String[] address = new String[1000];
	int i = 0;

	public void traverseDirectory(File file) throws Exception {

		if (file.isDirectory() & i < 1000) {
			String entries[] = file.list();

			if (entries != null) {
				for (String entry : entries) {
					traverseDirectory(new File(file, entry));
				}
			}
		} else {

			if (file.getAbsolutePath().endsWith(".java") && i < 1000) {
				address[i] = file.getAbsolutePath();
				System.out.println(address[i]);
				i++;
			}
		}
	}

	public String Extract() {
		String name = "Out.txt";
		StringBuilder result = null;
		try {
			BufferedWriter Out = new BufferedWriter(new FileWriter(name));
			Random r = new Random();

			FileInputStream fis = new FileInputStream(address[r.nextInt(1000)]);
			int size = (int) fis.available() * 5;
			byte[] text = new byte[size];

			fis.read(text, 0, size);
			String content = new String(text);

			StringTokenizer st = new StringTokenizer(content, DELIM);
			result = new StringBuilder();
			String space = " ";

			while (st.hasMoreTokens()) {
				String tok = st.nextToken();
				Pattern p = Pattern.compile(SPLIT_REGEX);
				Matcher m = p.matcher(tok);
				boolean found = m.find();
				while (found) {
					String subStringFound = m.group();
					if (1 < subStringFound.length()) {
						result.append(subStringFound + space);
					}
					found = m.find();
				}
			}
			Out.write(result.toString());
			fis.close();
			Out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return result.toString();

	}

	public static void main(String args[]) {
		RandomCode R = new RandomCode();
		try {
			File f = new File("D:\\ICSE12AT\\DataSet\\CodeSnippets\\Thread Pooling10\\T2\\New Folder");
			R.traverseDirectory(f);
			System.out.println(R.Extract());

		} catch (Exception ex) {
			Logger.getLogger(RandomCode.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

}
