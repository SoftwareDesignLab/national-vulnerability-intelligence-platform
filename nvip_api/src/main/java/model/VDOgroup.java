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
package model;

import java.util.HashMap;

public class VDOgroup {
	
	private String vdoGroupName;
	private HashMap<String, String> vdoLabel = new HashMap<String, String>();
	
	public VDOgroup(String vdoGroupName, String vdoLabel, String vdoConf) {
		super();
		this.vdoGroupName = vdoGroupName;
		this.vdoLabel.put(vdoLabel, vdoConf);
	}

	public String getVdoGroupName() {
		return vdoGroupName;
	}

	public void setVdoGroupName(String vdoGroupName) {
		this.vdoGroupName = vdoGroupName;
	}

	public HashMap<String, String> getVdoLabel() {
		return vdoLabel;
	}

	public void setVdoLabel(HashMap<String, String> vdoLabel) {
		this.vdoLabel = vdoLabel;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((vdoGroupName == null) ? 0 : vdoGroupName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		VDOgroup other = (VDOgroup) obj;
		if (vdoGroupName == null) {
			if (other.vdoGroupName != null)
				return false;
		} else if (!vdoGroupName.equals(other.vdoGroupName))
			return false;
		return true;
	}
	
	

}
