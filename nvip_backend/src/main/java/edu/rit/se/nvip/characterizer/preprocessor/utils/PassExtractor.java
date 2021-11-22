
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

/**
 *
 *
 * @author mmirak
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class PassExtractor {

	static int size = 2000000;
	static byte[] text = new byte[size];

	public PassExtractor() {

	}

	public void traverseDirectory(String tacticName, File file) throws Exception {

		if (file.isDirectory()) {
			String entries[] = file.list();

			if (entries != null) {
				for (String entry : entries) {
					traverseDirectory(tacticName, new File(file, entry));
				}
			}
		} else {

			if (file.getAbsolutePath().endsWith(".java")) {
				if (file.getName().contains(tacticName))
					System.out.println(file);

				// String code = readCode(file.getAbsolutePath());
				// String code = readCode(file.getAbsolutePath());
				// String temp[] = file.getAbsolutePath().split(projectName);
				// String filepath = temp[1];
				// String qualityType = "Unrelated";
				// if(relevantDocList.contains(filepath))
				// qualityType = tacticName;
				// db.insertCode(project, ++document_no, NFRConfig.TestDataTable,
				// file.getAbsolutePath(), filepath,
				// code, qualityType);
				// else

			}
		}
	}

	public static void run(String tacticName) throws Exception {
		String path = "D:\\ICSE12AT\\DataSet\\CodeSnippets\\Audit";
		File file = new File(path);
		int num = file.listFiles().length;
		byte[] text = new byte[124000];
		String content2 = " ";
		File[] f = file.listFiles();
		for (int i = 0; i < num; i++) {
			if (f[i].getAbsolutePath().contains(tacticName)) {
				FileInputStream fis = new FileInputStream(f[i].getAbsoluteFile());
				fis.read(text, 0, 124000);
				String content = new String(text);
				content2 = content2 + content;
				System.out.println(content2);
				fis.close();
			}
		}
		File ff = new File(path);
		FileOutputStream fs = new FileOutputStream(ff);
		fs.write(text);
		fs.close();

	}

	public static void main(String args[]) {

		PassExtractor p = new PassExtractor();
		File f = new File("D:\\ICSE12AT\\DataSet\\CodeSnippets\\Authenticate");

		try {
			p.traverseDirectory("Authenticate", f);
			// p.traverseDirectory("Unrelated", f);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}

}
